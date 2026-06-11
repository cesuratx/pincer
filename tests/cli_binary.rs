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

mod common;

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
        assert_eq!(json["schema"], "5", "{cmd}: envelope schema version");
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

/// The committed office capture with its last 7 bytes cut off — a record cut
/// short mid-file, the canonical degraded-but-not-broken input
/// (`truncated_tail` fires; exit stays 0 without `--strict`).
fn truncated_office(tag: &str) -> std::path::PathBuf {
    let bytes = std::fs::read(OFFICE).expect("committed sample");
    let cut = bytes.len().checked_sub(7).unwrap();
    let path = std::env::temp_dir().join(format!("pincer-trunc-{tag}-{}.pcap", std::process::id()));
    std::fs::write(&path, &bytes[..cut]).unwrap();
    path
}

/// `--strict` is the exit-code contract for degraded runs: 3 when anything
/// degraded, 0 otherwise — and never anything but 0 without the flag, so
/// existing pipelines keep working.
#[test]
fn strict_turns_degradation_into_exit_3() {
    let trunc = truncated_office("strict");

    let out = pincer(&["summary", trunc.to_str().unwrap(), "--strict"]);
    assert_eq!(
        out.status.code(),
        Some(3),
        "degraded + --strict must exit 3"
    );
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(
        text.contains("PARTIAL"),
        "the full report is still emitted: {text}"
    );

    let out = pincer(&["summary", trunc.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "without --strict degraded is 0");

    let out = pincer(&["summary", OFFICE, "--strict"]);
    assert_eq!(out.status.code(), Some(0), "clean + --strict stays 0");

    // The flag is global: it must also gate the DOT path.
    let out = pincer(&["deps", trunc.to_str().unwrap(), "--dot", "--strict"]);
    assert_eq!(out.status.code(), Some(3), "--strict applies to deps --dot");

    std::fs::remove_file(&trunc).ok();
}

/// Every table ends with the `# pincer:` footer — the completion marker a
/// pipe-truncated table cannot fake — carrying the row count, and the
/// PARTIAL reasons when degraded.
#[test]
fn table_footer_is_the_in_band_completion_marker() {
    let out = pincer(&["flows", OFFICE]);
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let last = text.lines().last().unwrap();
    assert!(
        last.starts_with("# pincer: ") && last.ends_with("row(s), complete"),
        "clean run must end with the completion footer: {last}"
    );

    let trunc = truncated_office("footer");
    let out = pincer(&["flows", trunc.to_str().unwrap()]);
    std::fs::remove_file(&trunc).ok();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    let last = text.lines().last().unwrap();
    assert!(
        last.contains("PARTIAL") && last.contains("truncated_tail"),
        "degraded run must name its damage in the footer: {last}"
    );
}

/// A degraded `deps --dot` leads with a `// pincer: PARTIAL` comment and is
/// still valid Graphviz; a clean graph carries no marker.
#[test]
fn dot_partial_header_appears_exactly_when_degraded() {
    let out = pincer(&["deps", OFFICE, "--dot"]);
    assert!(out.status.success());
    let dot = String::from_utf8(out.stdout).unwrap();
    assert!(!dot.contains("PARTIAL"), "clean graph must be unmarked");

    let trunc = truncated_office("dot");
    let out = pincer(&["deps", trunc.to_str().unwrap(), "--dot"]);
    std::fs::remove_file(&trunc).ok();
    assert!(out.status.success());
    let dot = String::from_utf8(out.stdout).unwrap();
    let first = dot.lines().next().unwrap();
    assert!(
        first.starts_with("// pincer: PARTIAL — ") && first.contains("truncated_tail"),
        "degraded graph must lead with the marker: {first}"
    );
    assert!(dot.contains("digraph dependencies {"));
    assert!(dot.trim_end().ends_with('}'), "still valid Graphviz");
}

/// The degrade-don't-discard contract end to end: a capture cut mid-record
/// exits 0, the warning lands on stderr, the envelope flips `truncated_tail`,
/// and stdout stays pure JSON — no warning text for a consumer to choke on.
#[test]
fn truncated_capture_warns_on_stderr_and_flags_the_envelope() {
    let trunc = truncated_office("warn");
    let out = pincer(&["summary", trunc.to_str().unwrap(), "--json"]);
    std::fs::remove_file(&trunc).ok();

    assert_eq!(out.status.code(), Some(0), "degraded is not broken");
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("pincer: warning:") && stderr.contains("truncated record"),
        "stderr must carry the truncation warning: {stderr}"
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        !stdout.contains("warning"),
        "warnings must never leak into stdout: {stdout}"
    );
    let json: serde_json::Value = serde_json::from_str(&stdout).expect("stdout is pure JSON");
    assert_eq!(
        json.pointer("/degradation/truncated_tail"),
        Some(&serde_json::Value::Bool(true)),
        "the envelope must flag the truncated tail"
    );
}

/// A well-framed pcapng whose SPB body is too short for its own `orig_len`
/// field is per-packet damage: the reader skips it, the count reaches both
/// stderr and the envelope, and the valid packet after it survives.
#[test]
fn malformed_spb_is_skipped_counted_and_warned() {
    let mut file = common::shb_le();
    file.extend_from_slice(&common::idb_le());
    // SPB framing claiming total_len 12: a zero-byte body with no room for
    // the mandatory orig_len field.
    file.extend_from_slice(&3u32.to_le_bytes());
    file.extend_from_slice(&12u32.to_le_bytes());
    file.extend_from_slice(&12u32.to_le_bytes());
    file.extend_from_slice(&common::epb_le(0, 0, &common::udp_frame(40000)));

    let out = common::run_on("bad-spb", &file, &["summary", "--json"]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "a skipped block degrades, never breaks: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        json.pointer("/degradation/skipped_blocks")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "the skipped block must reach the envelope"
    );
    assert_eq!(
        json.pointer("/data/packets")
            .and_then(serde_json::Value::as_u64),
        Some(1),
        "the valid packet after the bad SPB must survive"
    );
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(
        stderr.contains("malformed packet block"),
        "stderr must warn about the skipped block: {stderr}"
    );
}

/// The envelope's byte order is the salvage contract: `degradation` must
/// precede `data`, so a truncated JSON document can never be repaired into
/// data without its degradation record. Asserted on raw text — a parsed
/// Value cannot see key order.
#[test]
fn json_degradation_precedes_data_in_the_byte_stream() {
    for cmd in [
        "summary", "flows", "assets", "services", "deps", "dns", "dhcp",
    ] {
        let out = pincer(&[cmd, OFFICE, "--json"]);
        assert!(out.status.success());
        let text = String::from_utf8(out.stdout).unwrap();
        // Envelope keys sit at 2-space indent; data rows are nested deeper.
        let degradation_at = text
            .find("\n  \"degradation\":")
            .unwrap_or_else(|| panic!("{cmd}: degradation key missing"));
        let data_at = text
            .find("\n  \"data\":")
            .unwrap_or_else(|| panic!("{cmd}: data key missing"));
        assert!(
            degradation_at < data_at,
            "{cmd}: degradation must precede data in the bytes"
        );
        serde_json::from_str::<serde_json::Value>(&text).expect("stdout must stay valid JSON");
    }
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

/// Fresh per-test output directory under the system temp dir.
fn gen_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pincer-gen-{tag}-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn gen_refuses_to_write_through_a_symlink_destination() {
    #[cfg(unix)]
    {
        let dir = gen_dir("symlink");
        let victim = dir.join("victim.txt");
        std::fs::write(&victim, b"PRECIOUS DATA").unwrap();
        std::os::unix::fs::symlink(&victim, dir.join("office.pcap")).unwrap();

        let out = pincer(&["gen", dir.to_str().unwrap(), "--scenario", "office"]);

        assert_eq!(out.status.code(), Some(1), "symlink destination must fail");
        let err = String::from_utf8(out.stderr).unwrap();
        assert!(
            err.contains("not a regular file"),
            "stderr must say why: {err}"
        );
        assert_eq!(
            std::fs::read(&victim).unwrap(),
            b"PRECIOUS DATA",
            "the symlink target must be untouched"
        );
        assert!(
            dir.join("office.pcap")
                .symlink_metadata()
                .unwrap()
                .is_symlink(),
            "the planted symlink must not be replaced"
        );
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[test]
fn gen_leaves_only_complete_captures_and_no_tmp_debris() {
    let dir = gen_dir("clean");
    // Pre-existing regular files are replaced (the documented overwrite),
    // and stale temp debris from a crashed run must not block regeneration.
    std::fs::write(dir.join("office.pcap"), b"stale previous capture").unwrap();
    std::fs::write(dir.join("office.pcap.tmp"), b"debris").unwrap();

    let out = pincer(&["gen", dir.to_str().unwrap()]);
    assert!(out.status.success(), "gen must succeed in a fresh dir");

    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(
        names,
        ["incident.pcap", "office.pcap"],
        "only the final captures may remain — no .tmp debris"
    );
    // The replaced file must hold a complete capture the reader accepts.
    let summary = pincer(&["summary", dir.join("office.pcap").to_str().unwrap()]);
    assert!(summary.status.success(), "regenerated capture must parse");
    std::fs::remove_dir_all(&dir).ok();
}
