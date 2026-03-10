fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    println!("cargo:warning=MANIFEST_DIR is: {}", manifest_dir);

    let path = std::path::Path::new(&manifest_dir).join("../../gen/arm64-v8a");
    println!(
        "cargo:warning=LINKER_SEARCH_PATH is: {:?}",
        path.canonicalize()
    );

    println!("cargo:rustc-link-search=native={}", path.display());
    println!("cargo:rustc-link-lib=dylib=netrunner_client");

    tauri_build::build();
}
