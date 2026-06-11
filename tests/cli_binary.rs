//! True CLI integration tests: execute the compiled `pincer` binary and
//! assert its observable contract — exit codes, the versioned JSON envelope,
//! DOT structure, and stdout/stderr discipline. The in-memory pipeline tests
//! (`integration_cli.rs`) cannot see any of this.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::{Command, Output};

const OFFICE: &str = "testdata/office.pcap";

fn pincer(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_pincer"))
        .args(args)
        .output()
        .expect("binary must run")
}

#[test]
fn every_analysis_subcommand_emits_the_versioned_json_envelope() {
    for cmd in [
        "summary", "flows", "assets", "services", "deps", "dns", "dhcp",
    ] {
        let out = pincer(&[cmd, OFFICE, "--json"]);
        assert!(out.status.success(), "{cmd} --json must exit 0");
        let json: serde_json::Value =
            serde_json::from_slice(&out.stdout).expect("stdout must be pure JSON");
        assert_eq!(json["tool"], "pincer", "{cmd}: envelope tool field");
        assert_eq!(json["schema"], "4", "{cmd}: envelope schema version");
        assert_eq!(json["command"], cmd, "{cmd}: envelope discriminator");
        assert!(json.get("data").is_some(), "{cmd}: envelope data field");
        let degradation = json
            .get("degradation")
            .unwrap_or_else(|| panic!("{cmd}: degradation must always be present"));
        assert_eq!(
            degradation["truncated_tail"], false,
            "{cmd}: office capture is intact"
        );
        assert_eq!(
            degradation["damaged_section"], false,
            "{cmd}: office capture has no damaged section"
        );
        assert_eq!(degradation["skipped_blocks"], 0, "{cmd}: nothing skipped");
        assert_data_shape(cmd, &json["data"]);
    }
}

/// Field-level lock on each subcommand's JSON data shape: a silent rename or
/// removal of a key consumers parse must fail here, not in their pipelines.
fn assert_data_shape(cmd: &str, data: &serde_json::Value) {
    let required: &[&str] = match cmd {
        "summary" => &[
            "packets",
            "bytes",
            "duration_secs",
            "link_protocols",
            "anomalies",
        ],
        "flows" => &[
            "client",
            "server",
            "proto",
            "app",
            "packets",
            "bytes",
            "confirmed",
        ],
        "assets" | "services" => &["key", "macs", "ips", "hostnames", "services"],
        "deps" => &[
            "client",
            "client_label",
            "server",
            "server_label",
            "port",
            "proto",
        ],
        "dns" => &["role", "kind", "name", "value"],
        "dhcp" => &["msg_type", "client_mac", "hostname", "assigned_ip"],
        _ => &[],
    };
    let item = if data.is_array() {
        let arr = data.as_array().unwrap();
        assert!(!arr.is_empty(), "{cmd}: office capture must produce data");
        &arr[0]
    } else {
        data
    };
    for key in required {
        assert!(
            item.get(key).is_some(),
            "{cmd}: JSON data must carry the locked field {key:?}"
        );
    }
}

#[test]
fn summary_json_reports_the_anomaly_taxonomy() {
    let out = pincer(&["summary", OFFICE, "--json"]);
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let anomalies = &json["data"]["anomalies"];
    for key in [
        "truncated",
        "malformed",
        "undecodable",
        "skipped_blocks",
        "timestampless",
    ] {
        assert!(
            anomalies.get(key).is_some(),
            "anomalies must carry {key} so partial analysis is machine-detectable"
        );
    }
}

#[test]
fn summary_table_smoke() {
    let out = pincer(&["summary", OFFICE]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("packets"), "human summary names its counters");
}

#[test]
fn deps_dot_emits_identity_keyed_graphviz() {
    let out = pincer(&["deps", OFFICE, "--dot"]);
    assert!(out.status.success());
    let dot = String::from_utf8(out.stdout).unwrap();
    assert!(dot.starts_with("digraph dependencies {"));
    assert!(dot.trim_end().ends_with('}'));
    // Node declarations carry display names as labels; identity is the key.
    assert!(dot.contains("[label="), "nodes must declare labels");
}

#[test]
fn missing_file_fails_with_stderr_and_exit_1() {
    let out = pincer(&["summary", "no/such/file.pcap"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(out.stdout.is_empty(), "errors must not pollute stdout");
    assert!(!out.stderr.is_empty(), "error must be reported on stderr");
}

#[test]
fn garbage_file_fails_with_exit_1() {
    let path = std::env::temp_dir().join(format!("pincer-garbage-{}.pcap", std::process::id()));
    std::fs::write(&path, b"this is not a capture file at all").unwrap();
    let out = pincer(&["summary", path.to_str().unwrap()]);
    std::fs::remove_file(&path).ok();
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8(out.stderr).unwrap();
    assert!(
        err.contains("pcap") || err.contains("magic"),
        "stderr must say why: {err}"
    );
}

#[test]
fn unknown_arguments_exit_2() {
    assert_eq!(pincer(&["no-such-subcommand"]).status.code(), Some(2));
    assert_eq!(
        pincer(&["summary", OFFICE, "--bogus"]).status.code(),
        Some(2)
    );
}
