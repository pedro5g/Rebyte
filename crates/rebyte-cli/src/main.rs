//! Rebyte command-line entry point.

#![forbid(unsafe_code)]

fn main() {
    println!("rebyte {}", env!("CARGO_PKG_VERSION"));
}
