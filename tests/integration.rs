use std::process::Command;

fn bin() -> String {
    env!("CARGO_BIN_EXE_routels").to_string()
}

fn run(args: &[&str]) -> (i32, String, String) {
    let out = Command::new(bin())
        .args(args)
        .output()
        .expect("run routels");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn eos_good_is_clean() {
    let (code, out, err) = run(&["eos", "tests/fixtures/eos/good.cfg"]);
    assert_eq!(code, 0, "stdout: {out}\nstderr: {err}");
    assert!(out.is_empty(), "expected no diagnostics, got: {out}");
}

#[test]
fn eos_bad_has_errors() {
    let (code, out, _) = run(&["eos", "tests/fixtures/eos/bad.cfg"]);
    assert_ne!(code, 0);
    assert!(out.contains("EOS030"), "expected EOS030 in: {out}");
    assert!(
        out.contains("EOS010") || out.contains("duplicate"),
        "expected dup-iface diag in: {out}"
    );
    assert!(
        out.contains("EOS020") || out.contains("EOS041"),
        "expected bgp diag in: {out}"
    );
    assert!(
        out.contains("EOS040"),
        "expected stray neighbor diag in: {out}"
    );
}

#[test]
fn frr_good_is_clean() {
    let (code, out, _) = run(&["frr", "tests/fixtures/frr/good.cfg"]);
    assert_eq!(code, 0, "stdout: {out}");
}

#[test]
fn frr_bad_has_errors() {
    let (code, out, _) = run(&["frr", "tests/fixtures/frr/bad.cfg"]);
    assert_ne!(code, 0);
    assert!(out.contains("FRR020"), "asn error: {out}");
    assert!(out.contains("FRR060"), "network error: {out}");
}

#[test]
fn vyos_set_good_clean() {
    let (code, _, _) = run(&["vyos", "tests/fixtures/vyos/good.set"]);
    assert_eq!(code, 0);
}

#[test]
fn vyos_set_bad_errors() {
    let (code, out, _) = run(&["vyos", "tests/fixtures/vyos/bad.set"]);
    assert_ne!(code, 0);
    assert!(out.contains("VYO"), "expected VYO codes: {out}");
}

#[test]
fn vyos_curly_good_clean() {
    let (code, _, _) = run(&["vyos", "tests/fixtures/vyos/good.curly"]);
    assert_eq!(code, 0);
}

#[test]
fn vyos_curly_bad_errors() {
    let (code, out, _) = run(&["vyos", "tests/fixtures/vyos/bad.curly"]);
    assert_ne!(code, 0);
    assert!(
        out.contains("VYO034") || out.contains("unclosed"),
        "unclosed brace diag: {out}"
    );
}

#[test]
fn mikrotik_good_clean() {
    let (code, _, _) = run(&["mikrotik", "tests/fixtures/mikrotik/good.rsc"]);
    assert_eq!(code, 0);
}

#[test]
fn mikrotik_bad_errors() {
    let (code, out, _) = run(&["mikrotik", "tests/fixtures/mikrotik/bad.rsc"]);
    assert_ne!(code, 0);
    assert!(out.contains("ROS030"), "addr error: {out}");
    assert!(
        out.contains("ROS011") || out.contains("ROS010"),
        "path or bracket diag: {out}"
    );
}

#[test]
fn bird_good_clean() {
    let (code, out, _) = run(&["bird", "tests/fixtures/bird/good.conf"]);
    assert_eq!(code, 0, "out: {out}");
}

#[test]
fn bird_bad_errors() {
    let (code, out, _) = run(&["bird", "tests/fixtures/bird/bad.conf"]);
    assert_ne!(code, 0);
    assert!(out.contains("BIR"), "expected BIR diag: {out}");
}

#[test]
fn nft_good_clean() {
    let (code, _, _) = run(&["nft", "tests/fixtures/nft/good.nft"]);
    assert_eq!(code, 0);
}

#[test]
fn nft_bad_errors() {
    let (code, out, _) = run(&["nft", "tests/fixtures/nft/bad.nft"]);
    assert_ne!(code, 0);
    assert!(out.contains("NFT"), "expected NFT diag: {out}");
}

#[test]
fn iptables_good_clean() {
    let (code, _, _) = run(&["nft", "tests/fixtures/nft/good.iptables"]);
    assert_eq!(code, 0);
}

#[test]
fn debian_good_clean() {
    let (code, _, _) = run(&["debian", "tests/fixtures/debian/good.conf"]);
    assert_eq!(code, 0);
}

#[test]
fn debian_bad_errors() {
    let (code, out, _) = run(&["debian", "tests/fixtures/debian/bad.conf"]);
    assert_ne!(code, 0);
    assert!(out.contains("DEB"), "expected DEB codes: {out}");
}

#[test]
fn wireguard_good_clean() {
    let (code, out, _) = run(&["wireguard", "tests/fixtures/wireguard/good.conf"]);
    assert_eq!(code, 0, "out: {out}");
}

#[test]
fn wireguard_bad_errors() {
    let (code, out, _) = run(&["wireguard", "tests/fixtures/wireguard/bad.conf"]);
    assert_ne!(code, 0);
    assert!(out.contains("WG"), "expected WG codes: {out}");
}

#[test]
fn haproxy_good_clean() {
    let (code, out, _) = run(&["haproxy", "tests/fixtures/haproxy/good.cfg"]);
    assert_eq!(code, 0, "out: {out}");
}

#[test]
fn haproxy_bad_errors() {
    let (code, out, _) = run(&["haproxy", "tests/fixtures/haproxy/bad.cfg"]);
    assert_ne!(code, 0);
    assert!(out.contains("HAP"), "expected HAP codes: {out}");
}

#[test]
fn sysctl_good_clean() {
    let (code, _, _) = run(&["sysctl", "tests/fixtures/sysctl/good.conf"]);
    assert_eq!(code, 0);
}

#[test]
fn sysctl_bad_errors() {
    let (code, out, _) = run(&["sysctl", "tests/fixtures/sysctl/bad.conf"]);
    assert_ne!(code, 0);
    assert!(out.contains("SYS"), "expected SYS codes: {out}");
}

#[test]
fn deep_missing_tool_emits_hint_and_exits_zero() {
    // bird isn't installed on the CI runner; structural lint passes, deep fallback hint is non-fatal.
    let (code, out, _) = run(&["--deep", "bird", "tests/fixtures/bird/good.conf"]);
    assert_eq!(code, 0, "out: {out}");
    if !out.is_empty() {
        assert!(
            out.contains("DEEP404") || out.contains("DEEP-BIRD"),
            "expected DEEP hint or real bird diag: {out}"
        );
    }
}

#[test]
fn deep_container_required_for_eos() {
    let (code, out, _) = run(&["--deep", "eos", "tests/fixtures/eos/good.cfg"]);
    assert_eq!(code, 0, "out: {out}");
    assert!(
        out.contains("DEEP900"),
        "expected container-required hint: {out}"
    );
}

#[test]
fn sarif_format_is_valid_json_object() {
    let (_, out, _) = run(&["--format", "sarif", "frr", "tests/fixtures/frr/bad.cfg"]);
    let v: serde_json::Value = serde_json::from_str(&out).expect("sarif json");
    assert_eq!(v["version"], "2.1.0");
    let results = v["runs"][0]["results"].as_array().expect("results array");
    assert!(!results.is_empty(), "expected at least one sarif result");
    let r0 = &results[0];
    assert!(r0["ruleId"].is_string());
    assert!(r0["message"]["text"].is_string());
}

#[test]
fn json_format_emits_jsonl() {
    let (_code, out, _) = run(&["--format", "json", "eos", "tests/fixtures/eos/bad.cfg"]);
    for line in out.lines() {
        let v: serde_json::Value = serde_json::from_str(line).expect("valid jsonl");
        assert!(v.get("file").is_some());
        assert!(v.get("line").is_some());
        assert!(v.get("severity").is_some());
        assert!(v.get("code").is_some());
    }
}
