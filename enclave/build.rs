fn main() {
    println!("cargo:rustc-link-search=native=/root/xinjian/");
    println!("cargo:rustc-link-lib=static=test");

    println!("cargo:rustc-link-search=native=../lib/");
    println!("cargo:rustc-link-lib=static=enclave_tls");

    println!("cargo:rustc-link-search=native=../lib/");
    println!("cargo:rustc-link-lib=static=enclave_tls_u");
}
