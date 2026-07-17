//! MITRE reference catalogs (enrichment data, not detection rules).
//!
//! These catalogs — CWE today, CVE/CPE later — are *taxonomies* used to enrich
//! findings (annotate a bare `CWE-798` with its authoritative name and
//! description). They never enter the scan pipeline; a downloaded copy is
//! stored in the catalog database and looked up offline.
//!
//! The parsing ([`parse_cwe`]) is a pure function over bytes so it is testable
//! without the network; [`fetch_cwe`] is the thin download+unzip layer.

use std::io::Read;

use anyhow::{Context, Result};
use exfil_core::CweEntry;

/// The official CWE weakness catalog (a zipped XML file).
pub const CWE_URL: &str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip";

/// Parse the CWE catalog XML into weakness entries. Recognizes every
/// `<Weakness>` in the `<Weaknesses>` section, reading its `ID`, `Name`,
/// `Abstraction`, and `Status` attributes and its `<Description>` text.
pub fn parse_cwe(xml: &[u8]) -> Result<Vec<CweEntry>> {
    let text = std::str::from_utf8(xml).context("CWE XML is not UTF-8")?;
    let doc = roxmltree::Document::parse(text).context("parse CWE XML")?;
    let mut entries = Vec::new();
    for node in doc.descendants().filter(|n| n.has_tag_name("Weakness")) {
        let Some(id) = node.attribute("ID") else {
            continue;
        };
        let Some(name) = node.attribute("Name") else {
            continue;
        };
        let description = node
            .children()
            .find(|c| c.has_tag_name("Description"))
            .map(|d| normalize_ws(&text_of(d)))
            .unwrap_or_default();
        entries.push(CweEntry {
            id: format!("CWE-{id}"),
            name: name.to_string(),
            abstraction: node
                .attribute("Abstraction")
                .unwrap_or_default()
                .to_string(),
            status: node.attribute("Status").unwrap_or_default().to_string(),
            description,
        });
    }
    if entries.is_empty() {
        anyhow::bail!("no <Weakness> entries found in CWE XML");
    }
    Ok(entries)
}

/// Concatenate an element's descendant text (CWE descriptions can nest xhtml).
fn text_of(node: roxmltree::Node) -> String {
    node.descendants()
        .filter(roxmltree::Node::is_text)
        .filter_map(|n| n.text())
        .collect::<Vec<_>>()
        .join(" ")
}

/// Collapse runs of whitespace to single spaces and trim.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Download the CWE catalog zip from `url`, unzip the single XML entry, and
/// parse it. Online — this is the "pull" step; lookups afterward are offline.
pub async fn fetch_cwe(url: &str) -> Result<Vec<CweEntry>> {
    let bytes = reqwest::get(url)
        .await
        .with_context(|| format!("download CWE catalog from {url}"))?
        .error_for_status()
        .context("CWE catalog download failed")?
        .bytes()
        .await
        .context("read CWE catalog body")?;
    let xml = unzip_single(&bytes).context("unzip CWE catalog")?;
    parse_cwe(&xml)
}

/// Extract the first file from a zip archive as bytes (the CWE zip holds one
/// XML file).
fn unzip_single(zip_bytes: &[u8]) -> Result<Vec<u8>> {
    let reader = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(reader).context("open zip")?;
    if archive.is_empty() {
        anyhow::bail!("empty zip archive");
    }
    let mut file = archive.by_index(0).context("read first zip entry")?;
    let mut out = Vec::with_capacity(file.size() as usize);
    file.read_to_end(&mut out).context("extract zip entry")?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog Name="CWE" Version="4.20" xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="798" Name="Use of Hard-coded Credentials" Abstraction="Base" Status="Stable">
      <Description>The product contains hard-coded credentials, such as a
        password or cryptographic key.</Description>
    </Weakness>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
      <Description>Improper neutralization of input during web page generation.</Description>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>"#;

    #[test]
    fn parses_weaknesses_with_normalized_description() {
        let entries = parse_cwe(SAMPLE.as_bytes()).unwrap();
        assert_eq!(entries.len(), 2);
        let cwe798 = entries.iter().find(|e| e.id == "CWE-798").unwrap();
        assert_eq!(cwe798.name, "Use of Hard-coded Credentials");
        assert_eq!(cwe798.abstraction, "Base");
        assert_eq!(cwe798.status, "Stable");
        // Multi-line description is collapsed to single spaces.
        assert_eq!(
            cwe798.description,
            "The product contains hard-coded credentials, such as a password or cryptographic key."
        );
    }

    #[test]
    fn empty_or_invalid_xml_errors() {
        assert!(parse_cwe(b"<Weakness_Catalog></Weakness_Catalog>").is_err());
        assert!(parse_cwe(b"not xml at all <<<").is_err());
    }
}
