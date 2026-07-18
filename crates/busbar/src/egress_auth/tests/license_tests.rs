use std::path::Path;

/// M2: every first-party `.rs` file that declares an SPDX license MUST declare `Apache-2.0`.
/// cargo-deny only checks crate-level `Cargo.toml`, so a stray file header (the three new OAuth
/// files shipped as `AGPL-3.0-or-later`) would go undetected — this meta-test catches it. Files
/// with no SPDX line are ignored (headers are not mandatory); a WRONG one is a hard fail.
fn scan(dir: &Path, offenders: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            scan(&path, offenders);
        } else if path.extension().is_some_and(|x| x == "rs") {
            let head: String = std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .take(3)
                .collect::<Vec<_>>()
                .join("\n");
            if head.contains("SPDX-License-Identifier") && !head.contains("Apache-2.0") {
                offenders.push(path.display().to_string());
            }
        }
    }
}

#[test]
fn all_source_files_declare_apache_license() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    scan(&src, &mut offenders);
    assert!(
        offenders.is_empty(),
        "these first-party files declare a non-Apache-2.0 SPDX license: {offenders:#?}"
    );
}
