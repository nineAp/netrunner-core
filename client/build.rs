fn main() {
    println!("cargo:rerun-if-changed=netrunner_client.udl");
    uniffi::generate_scaffolding("src/netrunner_client.udl").unwrap()
}
