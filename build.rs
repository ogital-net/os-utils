fn main() {
    println!("cargo:rerun-if-changed=src/lib.c");

    cc::Build::new()
        .flag("-O2")
        .flag("-Wall")
        .file("src/lib.c")
        .compile("uptime");
}
