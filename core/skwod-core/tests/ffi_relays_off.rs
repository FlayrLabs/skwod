//! `p2p_relays_off` as the apps call it: through the generated bindings, from a foreign async
//! runtime (Python's asyncio) with no Tokio runtime around the call. Exported without
//! `async_runtime = "tokio"` it fails here; an app would see the same.
use std::path::PathBuf;
use std::process::Command;

#[test]
fn relays_off_works_through_the_ffi_without_an_ambient_runtime() {
    let bindgen = PathBuf::from(env!("CARGO_BIN_EXE_uniffi-bindgen"));
    let profile_dir = bindgen.parent().expect("profile dir");
    let name = format!("{}skwod_core{}", std::env::consts::DLL_PREFIX, std::env::consts::DLL_SUFFIX);
    let dylib = [profile_dir.join(&name), profile_dir.join("deps").join(&name)].into_iter().find(|p| p.exists()).expect("the cdylib is built with the tests");
    let out = tempfile::tempdir().expect("tempdir");
    let status = Command::new(&bindgen).args(["generate", "--no-format", "--library"]).arg(&dylib)
        .args(["--language", "python", "--out-dir"]).arg(out.path()).status().expect("uniffi-bindgen runs");
    assert!(status.success());
    std::fs::copy(&dylib, out.path().join(&name)).expect("copy the cdylib next to the bindings");
    let run = Command::new("python3").current_dir(out.path())
        .args(["-c", "import asyncio, skwod_core; print('closed', asyncio.run(skwod_core.p2p_relays_off()))"])
        .output().expect("python3 runs");
    let text = format!("{}{}", String::from_utf8_lossy(&run.stdout), String::from_utf8_lossy(&run.stderr));
    assert!(run.status.success() && text.contains("closed None"), "{text}");
}
