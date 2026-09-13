// Reads version.json, the project's single source of truth for the release
// version (stage2/config.py reads the same file at runtime), and exposes it
// to main.rs as the FLOD_VERSION compile-time env var. Cargo.toml's own
// `version` field stays unedited from here on; nothing reads it at runtime.
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not set");
    let version_path = Path::new(&manifest_dir).join("..").join("version.json");
    println!("cargo:rerun-if-changed={}", version_path.display());

    let version = fs::read_to_string(&version_path)
        .ok()
        .and_then(|contents| serde_json::from_str::<serde_json::Value>(&contents).ok())
        .and_then(|v| v.get("version").and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());

    println!("cargo:rustc-env=FLOD_VERSION={version}");
}
