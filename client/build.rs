fn main() {
    println!("cargo:rerun-if-changed=netrunner_client_core.udl");
    uniffi::generate_scaffolding("src/netrunner_client_core.udl").unwrap()
}
