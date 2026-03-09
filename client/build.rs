fn main() {
    println!("cargo:rerun-if-changed=client.udl");
    uniffi::generate_scaffolding("./client.udl").expect("Can't generate UniFFI files");
}
