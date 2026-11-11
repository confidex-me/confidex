use std::{env, path::PathBuf, process::Command};
fn main() {
    println!("cargo:rerun-if-changed=src/platform/enclave.swift");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("macos") {
        return;
    }
    let architecture = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "arm64",
        Ok("x86_64") => "x86_64",
        _ => panic!("unsupported macOS architecture"),
    };
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let archive = out.join("libconfidex_enclave.a");
    let status = Command::new("xcrun")
        .args([
            "swiftc",
            "-parse-as-library",
            "-emit-library",
            "-static",
            "-O",
            "-module-name",
            "ConfidexDeviceSecrets",
            "-target",
            &format!("{architecture}-apple-macosx10.15"),
            "src/platform/enclave.swift",
            "-o",
        ])
        .arg(&archive)
        .status()
        .expect("macOS backend needs the Swift compiler from Xcode Command Line Tools");
    assert!(status.success(), "Secure Enclave bridge compilation failed");
    let sdk = Command::new("xcrun")
        .arg("--show-sdk-path")
        .output()
        .expect("Xcode SDK path");
    assert!(sdk.status.success(), "Xcode SDK lookup failed");
    println!("cargo:rustc-link-search=native={}", out.display());
    println!(
        "cargo:rustc-link-search=native={}/usr/lib/swift",
        String::from_utf8(sdk.stdout).unwrap().trim()
    );
    println!("cargo:rustc-link-search=native=/usr/lib/swift");
    let compiler = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .expect("Swift compiler path");
    assert!(compiler.status.success(), "Swift compiler lookup failed");
    let compiler = PathBuf::from(String::from_utf8(compiler.stdout).unwrap().trim());
    let runtime = compiler
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("lib/swift/macosx");
    println!("cargo:rustc-link-search=native={}", runtime.display());
    println!("cargo:rustc-link-lib=static=confidex_enclave");
}
