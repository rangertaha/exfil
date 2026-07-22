# Continuous Integration

exfil fits a pipeline two ways, and they compose:

1. **Gate the build** — fail the job when findings cross a severity threshold.
2. **Report findings** — upload a machine-readable report so they show up in
   your platform's UI (GitHub code scanning, a JUnit test view, a dashboard).

The core filesystem, code, and archive scanning is fully offline, so it runs on
any runner without network access.

## Gate a build with `--fail-on`

`exfil scan --fail-on <severity>` exits non-zero when any stored finding is at
or above the given level (`info|low|medium|high|critical`):

```sh
exfil scan --fail-on high  # exit 1 if any high/critical finding exists
```

That single line is enough to break a build on real problems. The check runs
against the whole store, so an incremental scan gates on the cumulative state.

## GitHub code scanning (SARIF)

[SARIF](https://sarifweb.azurewebsites.net/) is the standard GitHub code
scanning ingests to annotate findings inline on pull requests. Scan, render a
SARIF report, and upload it:

```yaml
name: exfil
on: [push, pull_request]

permissions:
  contents: read
  security-events: write        # required to upload SARIF

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install exfil
        run: cargo install --git https://github.com/rangertaha/exfil exfil-cli

      - name: Scan
        run: exfil scan .

      - name: Render SARIF
        run: exfil analyze --format sarif > exfil.sarif

      - name: Upload to code scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: exfil.sarif
```

Findings then appear under the repository's **Security → Code scanning** tab and
as inline annotations on the pull request. Note the `security-events: write`
permission — the upload step needs it.

To *also* fail the job on high-severity findings, gate the scan step and let the
SARIF upload run regardless:

```yaml
      - name: Scan
        run: exfil scan . --fail-on high

      - name: Render SARIF
        if: always()            # upload findings even when the gate failed
        run: exfil analyze --format sarif > exfil.sarif
```

## Other CI systems (JUnit)

Systems that ingest JUnit XML (Jenkins, GitLab CI, GitHub Actions test
reporters) can read a JUnit report, where each finding is a failing test case:

```sh
exfil scan .
exfil analyze --format junit > exfil-junit.xml
```

A clean scan produces a passing suite (zero failures), so the report goes green
when there is nothing to report.
