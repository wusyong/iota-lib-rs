fn main() {
    println!("cargo:rustc-link-search=native=/home/wusyong/Desktop/iota.rs/iota-core/src/");
    println!("cargo:rustc-link-lib=static=keccak");
    println!("cargo:rustc-link-lib=static=common");
}
