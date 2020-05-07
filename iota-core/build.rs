fn main() {
    println!("cargo:rustc-link-search=native=your_path_to/iota-core/src/");
    println!("cargo:rustc-link-lib=static=keccak");
    println!("cargo:rustc-link-lib=static=common");
}
