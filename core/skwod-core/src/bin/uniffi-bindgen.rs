//! Bindings generator entrypoint. Run:
//!   cargo run --bin uniffi-bindgen -- generate --library <path-to-dylib> --language swift --out-dir <dir>
fn main() {
    uniffi::uniffi_bindgen_main()
}
