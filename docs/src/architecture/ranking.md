# 9 · Ranked scanning (`model` · `plan`)

← [Integrations](./integrations.md) · Next: [Rust primer →](./rust-primer.md)

Everything up to here scans **everything**. This page is about scanning the
*right things first*, and about stopping early without lying about what you did.

Two pieces:

- **`exfil-model`** — a hidden Markov model over filesystem paths, trained on the
  scans already in your graph, that estimates `P(finding | path)`.
- **`exfil-engine::plan`** — the [`Budget`](#budgets) and [`ScanPlan`](#the-plan)
  that turn that estimate into an ordering and a stopping rule.

---

## 1. Why a model at all

A scan of a large tree spends most of its time in places that will never yield
anything — `node_modules`, build output, vendored copies, documentation. The
information to avoid that is already sitting in the graph: every previous scan
recorded which files carried findings and which didn't.

That's a labelled corpus. No new scanning, no hand-labelling:

```text
  store                                    training samples
  ┌──────────────────────────┐
  │ file  /home/u/p/key.pem  │◄── in_file ──┐   ("/home/u/p/key.pem",  true)
  │ file  /home/u/p/README   │              │   ("/home/u/p/README",  false)
  │ finding aws-access-key   │──────────────┘   …
  └──────────────────────────┘
```

`Store::training_paths()` returns exactly that: every recorded file's path,
paired with whether any finding was ever attached to it.

> **Caveat worth knowing.** `file` records are keyed by content hash, so files
> with *identical content* collapse to a single record with one arbitrary path.
> Training samples are therefore distinct **contents**, not distinct paths. Real
> trees are mostly unique so this is survivable, but duplicated content
> (vendored libraries, repeated headers) contributes once rather than many times.

---

## 2. Why a *sequence* model

A path is not a bag of words. `.ssh` under a user's home means something quite
different from `.ssh` under `/tmp/build-1234`, and only a model that conditions
on what came before can tell them apart. That conditioning is the entire
argument for a Markov chain over a simple frequency table — and it is worth
measuring, because a bag-of-components baseline is thirty lines and will capture
a surprising fraction.

The tokenizer ([`model/tokens.rs`](../../crates/exfil-model/src/tokens.rs)) lowercases
each path component and replaces the **filename with its extension**:

```text
  /home/tsd/proj/secrets/report-2024-final.pem
   home   tsd   proj   secrets   <ext:pem>
```

Filenames are near-unique, so they carry almost no transferable signal and would
bloat the vocabulary. `.pem` means something everywhere;
`report-2024-final.pem` means something only here.

---

## 3. Two chains, not one {#two-chains}

This is the part that took two attempts, and the failure is instructive.

**The first design** fitted one chain over all paths and read a per-state risk
off it: `P(finding | state)` estimated from the labels, then
`score = Σ γ(i)·risk[i]`. It scored `secrets/` and `vendor/` *identically*.

That is not a bug that can be patched. **Baum-Welch maximises likelihood, and
the labels take no part in fitting.** A single state that emits `secrets`,
`docs` and `vendor` with equal probability is a perfectly good model of the
corpus — the likelihood objective has no reason to prefer separating them. Once
the model has collapsed them into one state, no read-out over states can pull
them apart.

The fix is the standard one for a generative classifier: **one chain per class**,
scored by likelihood ratio. Making the label pick the chain is what gives
training a reason to tell the families apart.

```mermaid
flowchart LR
    P["/home/u/proj/secrets/key.pem"] --> T["tokenize"]
    T --> POS["positive chain<br/>fitted on paths WITH findings"]
    T --> NEG["negative chain<br/>fitted on paths WITHOUT"]
    POS --> R["log P(path | finding)"]
    NEG --> S["log P(path | no finding)"]
    R & S --> SIG["σ(Δ + log-odds of base rate)"]
    SIG --> OUT["P(finding | path)"]
```

Everything is computed in log space and combined with a logistic: the
likelihoods themselves are astronomically small for a long path, and only their
*ratio* carries meaning.

### Numerical care

Multiplying hundreds of probabilities underflows `f64` to zero within a few
dozen steps, which would silently return a score of zero for any deep path. The
forward-backward recursions are therefore **scaled** — each timestep normalised,
the scale factors kept to recover the log-likelihood (the standard Rabiner
formulation). Viterbi works in logs for the same reason. A test scans a
400-component path specifically to prove this doesn't regress.

### Determinism

Baum-Welch cannot break symmetry on its own: start every state identical and
they stay identical forever. Rather than an RNG and a seed to thread around,
each state gets a deterministic integer-hash tilt, so **the same corpus always
produces the same model** — a property a test asserts, and one you want when a
model's output influences what gets scanned.

---

## 4. Budgets {#budgets}

`Budget` ([`engine/plan.rs`](../../crates/exfil-engine/src/plan.rs)) parses from
a suffixed string, so one flag covers every unit:

| Input | Meaning | Reproducible? |
|---|---|---|
| `20%` | fraction of files found | yes |
| `2000` | file count | yes |
| `500mb` | bytes read | yes |
| `30s`, `5m`, `1h` | wall-clock | **no** |
| `90c`, `90%c` | share of the *expected findings* | yes |

Percentages and counts are deterministic and safe for CI. A time budget isn't —
two runs on the same commit scan different sets — which is why the resulting
file set is recorded in the scan record: non-deterministic when it happens, but
auditable afterwards.

Ranking is by **expected value, not probability**:

```text
                P(finding | path)
   value  =  ─────────────────────       cost floored at one filesystem block
                   cost(bytes)
```

A 2 GB disk image at p=0.9 is worse value than five hundred dotfiles at p=0.3.
It's a greedy knapsack by ratio.

### Confidence, the budget that adapts {#confidence}

Every other budget caps **cost**. `90c` caps **uncertainty**: scan in ranked
order until the files examined account for 90% of the total expected findings,
where "expected" is the sum of the calibrated probabilities.

```text
expected  │      ╭─────────────  ← the knee: nearly everything of value found
 findings │    ╭─╯
    found │  ╭─╯
          │╭─╯
          └──────────────────── files scanned, ranked
               ▲
               90c stops here — wherever that happens to be
```

That is the one budget that adapts to the tree. Risk concentrated in a handful
of files stops almost immediately; risk spread thin keeps going. No fixed
percentage can do that, because it has to assume a shape in advance.

It only means anything with a **calibrated** model — it sums probabilities, so
if those aren't probabilities the target isn't either. That is why this arrived
after [calibration](#calibration) rather than alongside `--budget`.

---

## 5. The plan, and the two-phase walk {#the-plan}

`ScanPlan { model, budget, ruleset }` is what a front end hands the engine. With
neither a model nor a budget, the engine takes the ordinary streaming walk —
there is nothing to order and nothing to stop, and the simpler path is faster.

With either, it switches to a two-phase walk:

```text
  ordinary                ranked
  ────────                ──────
  walk ──► process        walk ──► score      (stat only, no reads)
           each file                ↓ sort by value/cost
           as found              process in order, stopping on budget
```

The scoring pass **replaces** the old `count_files` pre-walk rather than adding
to it — that traversal already existed purely to give the progress gauge a
denominator, so ranking costs no extra walk.

### Changed files always win

The ordering is lexicographic, not one score:

```text
  rank 1   changed / new files    ← the stat index knows these exactly
  rank 2   unchanged files        ← ordered by model value
```

Only changed files can produce *new* findings, and the stat index knows which
they are with certainty. **No prior beats a fact.** The model decides the order
within each group, not between them.

---

## 6. Saying what you didn't do

A scanner that covers 20% and prints `0 findings` is dangerous if the output
reads like a clean scan. Three rules enforce that it can't:

1. **The summary states coverage.** `Summary::is_partial()` and `coverage()`
   drive a line naming how many files were examined, how many weren't, and
   whether the order was probability-ranked or merely walk order.
2. **`--budget` and `--fail-on` cannot be combined.** Clap rejects it. A green
   CI badge from a 20% scan is a lie, and the cleanest way not to tell it is to
   make it unrepresentable.
3. **The MCP `scan` tool** appends an explicit *"absence of findings does not
   mean the target is clean"* to any partial result, because an agent reading
   tool output has even less context than a human reading a terminal.

There is a fourth, quieter one: `--budget` on a target that can't honour it (a
crawl, a port sweep) **warns** rather than silently running a full scan.

---

## 7. The ruleset fingerprint {#fingerprint}

Ranking and budgeting made an existing bug much sharper, so it was fixed
alongside them.

The stat fast-path skips a file whose size and mtime match the last scan. That
promise only holds **for the rules that produced the stored findings**. Pull a
new dataset, rescan, and every unchanged file stays unexamined by rules that
have never seen it — a silent miss.

`setup::ruleset_fingerprint()` hashes every active rule's name and pattern
(sorted, so merely reordering a dataset doesn't force a rescan). Each scan
records it; when the next scan's fingerprint differs, the fast-path is bypassed,
everything is re-examined exactly once, and the fingerprint settles again.

```mermaid
flowchart LR
    A["scan #1<br/>ruleset aaaa"] --> B["rescan<br/>ruleset aaaa"]
    B -->|fast-path applies| C["unchanged files skipped"]
    A --> D["exfil dataset update …"]
    D --> E["rescan<br/>ruleset bbbb"]
    E -->|fingerprint moved| F["fast-path bypassed<br/>everything re-examined"]
    F --> G["fingerprint settles<br/>fast-path resumes"]
```

The same fingerprint is stored on a trained model, so a model fitted under one
ruleset **warns** rather than silently ranking on stale assumptions.

---

## 8. Using it

```sh
exfil scan ./project              # populate the graph first
exfil train                       # fit on what's there
exfil model get                   # states, vocabulary, base rate, ruleset
exfil model score src/auth/key.pem
                                  # probability + per-component log-odds

exfil scan ./project --ranked        # worst-first, still scans everything
exfil scan ./project --budget 20%    # worst-first, stops at 20%
exfil scan ./project --budget 30s    # …or after 30 seconds
```

Agents reach the same three via the MCP tools `hmm_train`, `hmm_score` and
`hmm_status` ([Integrations](./integrations.md)).

---

## 9. Calibration {#calibration}

Ranking and *probability* are different properties, and only the second licenses
acting on the number.

A likelihood ratio between two chains is enormously confident: on a separable
corpus the raw scores pile up at exactly 1.0 and 0.0. That ranks perfectly well
— ordering is all `--budget` needs — but "1.0" as a probability is a claim no
model should make, and a `--confidence` stop condition computed from such
numbers would be meaningless.

So the raw log-odds are passed through a **Platt scaling** — a two-parameter
logistic fitted by gradient descent on cross-entropy:

```text
   raw:  log P(path | finding) − log P(path | no finding)   (+ base-rate log-odds)
                          │
                   σ(a·z + b)          a, b fitted on held-out predictions
                          │
   calibrated:  P(finding | path)
```

Two details carry the weight:

- **Fitted out of fold.** Calibrating on the paths the chains were fitted on
  would be circular — the model has seen those labels, its log-odds on them are
  unrealistically confident, and the map would bake that overconfidence in
  rather than correct it. A throwaway model is fitted on part of the corpus and
  scored on the rest; the calibration is learned from *those* predictions and
  then applied to the full-data chains.
- **It cannot change the ranking.** A logistic with a positive slope is
  monotonic, so recall-at-budget is identical before and after. `fit_platt`
  refuses a non-positive slope and falls back to the identity, and a test
  asserts the two orderings match — calibration must never cost ranking quality.

When there is too little data to hold anything out, the map stays at the
identity and `model status` says `uncalibrated` rather than pretending.

Quality is measured, not asserted. `model eval` reports:

- **Brier score** — mean squared error between predicted probability and
  outcome. Always guessing the base rate scores about 0.25.
- **Expected calibration error** — the average gap between claimed probability
  and observed frequency across ten bins. Above ~0.15 the values should be read
  as a ranking only, and the output says so.

```text
calibration: Brier 0.008, expected error 0.067
```

Before this, `secrets/x.env` scored a flat `1.0000`. It now scores `0.9000`,
which is a statement you can act on.

---

## 10. Measuring it: `exfil model eval` {#eval}

The claim is "at N% of the work you recover far more than N% of the findings".
[`model/eval.rs`](../../crates/exfil-model/src/eval.rs) checks it, and is built to
avoid the three ways you can fool yourself:

- **Out of sample.** Paths are split train/test by a deterministic hash of the
  path — no RNG, so re-running gives the same answer and a lucky split can't
  masquerade as an improvement. Scoring the paths the model was fitted on would
  measure memorisation, not prediction.
- **Against a real baseline.** "Beats random" is a low bar. The bar that matters
  is a **frequency prior over the parent directory** — thirty lines, no sequence
  modelling at all.
- **Against random.** At budget *b*, blind selection recovers *b*. That's the
  floor.

```text
$ exfil model eval
trained on 109 path(s), measured on 51 held out (14 with findings)

   budget    model  baseline  random   lift
       5%      21%       21%      5%   4.3x
      10%      43%       43%     10%   4.3x
      20%      79%       79%     20%   3.9x
      30%     100%      100%     30%   3.3x

mean lift over blind selection: 3.2x
VERDICT: a plain directory-frequency prior does as well. The sequence model is
not earning its complexity on this corpus.
```

**Read that verdict carefully — it is the common case.** On a corpus where the
directory name alone explains the label (`secrets/` always has findings,
`docs/` never does), a frequency table matches the path model exactly. The 3.2× lift
over blind selection is real and useful; the *sequence modelling* contributes
nothing.

The sequence model earns its keep only where **context disambiguates**:

```text
  /srv/deploy/config/*.env   → findings        same directory name,
  /var/cache/config/*.env    → none            opposite labels
```

A prior keyed on `config` sees half positives and half negatives and cannot do
better than chance. A model that conditions on the prefix separates them. A test
(`context_dependent_corpus_is_where_the_sequence_model_wins`) pins exactly that,
and the complementary test pins the case where the baseline ties.

So the honest position: **run `model eval` on your own corpus before trusting
`--budget`.** If it reports the baseline tying, ranked scanning still helps a
great deal over scanning in walk order — but a much simpler model would do the
same job, and that is worth knowing.

## 11. What isn't done

Stated plainly, because a probability that looks authoritative and isn't is
worse than no probability at all:

- **The sequence model does not always earn its complexity.** `exfil model eval`
  measures this and says so out loud — see below.

---

---

**Next:** the [Rust primer](./rust-primer.md) collects every Rust concept these
pages leaned on.
