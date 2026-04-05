//! Integration benchmark: 10k lookups through the daemon via HTTP and CLI.
//!
//! Run with: cargo test --release --package misp-fbd bench_10k -- --nocapture --ignored

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use reqwest::blocking::Client;
use serde_json::json;

/// Test corpus: values that hit all five matcher types plus misses.
fn build_corpus() -> Vec<&'static str> {
    let cidr_values = [
        "8.8.8.8",
        "8.8.4.4",
        "1.1.1.1",
        "2606:4700::1111",
        "103.11.223.1",
        "1.178.1.50",
        "194.187.176.130",
        "45.83.64.1",
        "13.32.0.1",
        "20.33.0.1",
    ];

    let hostname_values = [
        "google.com",
        "facebook.com",
        "youtube.com",
        "mail.google.com",
        "cdn.amazonaws.com",
        "api.github.com",
        "10086.cn",
        "115.com",
        "www.apple.com",
        "login.microsoftonline.com",
    ];

    let string_values = [
        "1-courier.push.apple.com",
        "android.clients.google.com",
        "captive.apple.com",
        "apple.com",
        "1.nflxso.net",
        "icanhazip.com",
        "cloudflare.com",
        "microsoft.com",
        "amazon.com",
        "github.com",
    ];

    let substring_values = [
        "https://capesandbox.com/analysis/12345",
        "http://analyze.intezer.com/files/test",
        "https://anlyz.io/sample/abc",
        "http://akana.mobiseclab.org/report",
        "https://portal.docdeliveryapp.com/test",
        "http://portal.docdeliveryapp.net/phish",
        "https://app.any.run/tasks/12345",
        "http://bazaar.abuse.ch/sample/abc",
        "https://capesandbox.com/submit",
        "http://anlyz.io/details/xyz",
    ];

    let regex_values = [
        "abuse@example.com",
        "security@company.org",
        "noc@bigcorp.net",
        "soc@defense.io",
        "abuse@university.edu",
        "security@bank.com",
        "noc@isp.net",
        "soc@gov.mil",
        "abuse@hosting.co",
        "security@startup.io",
    ];

    let miss_values = [
        "this-does-not-match-anything-12345.zzz",
        "192.0.2.1",
        "definitely-not-a-real-domain.invalid",
        "random-gibberish-abc123",
        "user@nonexistent-domain-xyz.test",
        "198.51.100.200",
        "unknown-service.example.test",
        "zzzz-no-match.local",
        "fake-indicator-00000",
        "203.0.113.50",
    ];

    let mut corpus = Vec::with_capacity(10_000);
    for i in 0..10_000 {
        let val = match i % 5 {
            0 => cidr_values[i / 5 % cidr_values.len()],
            1 => hostname_values[i / 5 % hostname_values.len()],
            2 => {
                if (i / 5) % 2 == 0 {
                    string_values[i / 5 % string_values.len()]
                } else {
                    substring_values[i / 5 % substring_values.len()]
                }
            }
            3 => regex_values[i / 5 % regex_values.len()],
            _ => miss_values[i / 5 % miss_values.len()],
        };
        corpus.push(val);
    }
    corpus
}

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn daemon_binary() -> PathBuf {
    let mut path = PathBuf::from(env!("CARGO_BIN_EXE_misp-fbd"));
    // In case the integration test binary is in a different profile dir,
    // fall back to looking relative to the project root.
    if !path.exists() {
        path = project_root().join("target/release/misp-fbd");
    }
    path
}

fn cli_binary() -> PathBuf {
    // The CLI binary is in the same directory as the daemon binary
    let daemon = daemon_binary();
    daemon.parent().unwrap().join("misp-fb")
}

struct DaemonGuard {
    child: std::process::Child,
    socket_path: PathBuf,
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

fn start_daemon(http_port: u16) -> DaemonGuard {
    let root = project_root();
    let socket_path = std::env::temp_dir().join(format!("misp-fbd-bench-{}.sock", http_port));
    let _ = std::fs::remove_file(&socket_path);

    // Write a temporary config
    let config_path = std::env::temp_dir().join(format!("misp-fbd-bench-{}.toml", http_port));
    let config = format!(
        r#"[daemon]
socket_path = "{}"
http_bind = "127.0.0.1:{}"
warninglists_path = "{}"

[warninglists]
lists = []
"#,
        socket_path.display(),
        http_port,
        root.join("misp-warninglists/lists").display()
    );
    std::fs::write(&config_path, &config).expect("Failed to write test config");

    let child = Command::new(daemon_binary())
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start misp-fbd");

    let guard = DaemonGuard {
        child,
        socket_path: socket_path.clone(),
    };

    // Wait for daemon to be ready (poll the health endpoint)
    let client = Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/health", http_port);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline {
            panic!("Daemon failed to start within 30 seconds");
        }
        if let Ok(resp) = client.get(&url).send() {
            if resp.status().is_success() {
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }

    guard
}

#[test]
#[ignore] // Run explicitly: cargo test --release --package misp-fbd bench_10k -- --nocapture --ignored
fn bench_10k_http_and_cli() {
    let corpus = build_corpus();
    let http_port = 19384; // Unlikely to collide
    let _daemon = start_daemon(http_port);

    eprintln!();
    eprintln!("  Daemon ready, starting benchmarks...");
    eprintln!();

    // ── HTTP: individual lookups ────────────────────────────────────
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap();
    let lookup_url = format!("http://127.0.0.1:{}/lookup", http_port);

    // Warm up
    for val in corpus.iter().take(50) {
        let _ = client
            .post(&lookup_url)
            .json(&json!({ "value": val }))
            .send();
    }

    let start = Instant::now();
    let mut http_hits = 0usize;
    let mut http_total_matches = 0usize;
    for val in &corpus {
        let resp = client
            .post(&lookup_url)
            .json(&json!({ "value": val }))
            .send()
            .expect("HTTP request failed");
        let body: serde_json::Value = resp.json().expect("Invalid JSON response");
        if body["matched"].as_bool().unwrap_or(false) {
            http_hits += 1;
            http_total_matches += body["matches"].as_array().map(|a| a.len()).unwrap_or(0);
        }
    }
    let http_individual_elapsed = start.elapsed();

    eprintln!("  ── HTTP: 10k individual POST /lookup ──");
    eprintln!("  Total time:       {:?}", http_individual_elapsed);
    eprintln!(
        "  Per request (avg): {:?}",
        http_individual_elapsed / corpus.len() as u32
    );
    eprintln!(
        "  Requests/sec:      {:.0}",
        corpus.len() as f64 / http_individual_elapsed.as_secs_f64()
    );
    eprintln!(
        "  Hit rate:          {}/{} ({:.1}%)",
        http_hits,
        corpus.len(),
        http_hits as f64 / corpus.len() as f64 * 100.0
    );
    eprintln!(
        "  Total matches:     {} (avg {:.1} per hit)",
        http_total_matches,
        http_total_matches as f64 / http_hits.max(1) as f64
    );
    eprintln!();

    // ── HTTP: batch lookup ──────────────────────────────────────────
    let batch_url = format!("http://127.0.0.1:{}/lookup/batch", http_port);

    let start = Instant::now();
    let resp = client
        .post(&batch_url)
        .json(&json!({ "values": &corpus }))
        .send()
        .expect("Batch HTTP request failed");
    let body: serde_json::Value = resp.json().expect("Invalid JSON response");
    let http_batch_elapsed = start.elapsed();

    let results = body["results"].as_array().unwrap();
    let batch_hits: usize = results
        .iter()
        .filter(|r| r["matched"].as_bool().unwrap_or(false))
        .count();
    let batch_total_matches: usize = results
        .iter()
        .map(|r| r["matches"].as_array().map(|a| a.len()).unwrap_or(0))
        .sum();

    eprintln!("  ── HTTP: single POST /lookup/batch (10k values) ──");
    eprintln!("  Total time:       {:?}", http_batch_elapsed);
    eprintln!(
        "  Per value (avg):   {:?}",
        http_batch_elapsed / corpus.len() as u32
    );
    eprintln!(
        "  Values/sec:        {:.0}",
        corpus.len() as f64 / http_batch_elapsed.as_secs_f64()
    );
    eprintln!(
        "  Hit rate:          {}/{} ({:.1}%)",
        batch_hits,
        corpus.len(),
        batch_hits as f64 / corpus.len() as f64 * 100.0
    );
    eprintln!(
        "  Total matches:     {} (avg {:.1} per hit)",
        batch_total_matches,
        batch_total_matches as f64 / batch_hits.max(1) as f64
    );
    eprintln!();

    // ── CLI: individual lookups ───────────────────────────────────────
    // Each invocation spawns a process, connects to the socket, and prints
    // the result, so we use a smaller sample (200) and extrapolate.
    const CLI_INDIVIDUAL_COUNT: usize = 200;

    let cli = cli_binary();
    let mut cli_individual_elapsed = None;
    if cli.exists() {
        let socket_path = std::env::temp_dir()
            .join(format!("misp-fbd-bench-{}.sock", http_port));
        let socket_str = socket_path.display().to_string();

        // Warm up
        let _ = Command::new(&cli)
            .args(["--socket", &socket_str, "check", "8.8.8.8"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let start = Instant::now();
        let mut cli_ind_hits = 0usize;
        for val in corpus.iter().take(CLI_INDIVIDUAL_COUNT) {
            let output = Command::new(&cli)
                .args(["--socket", &socket_str, "-f", "csv", "check", val])
                .output()
                .expect("Failed to run misp-fb");
            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.contains(",true,") {
                cli_ind_hits += 1;
            }
        }
        let elapsed = start.elapsed();
        cli_individual_elapsed = Some(elapsed);

        eprintln!("  ── CLI: {} individual `misp-fb check <value>` ──", CLI_INDIVIDUAL_COUNT);
        eprintln!("  Total time:       {:?}", elapsed);
        eprintln!(
            "  Per invocation:    {:?}",
            elapsed / CLI_INDIVIDUAL_COUNT as u32
        );
        eprintln!(
            "  Invocations/sec:   {:.0}",
            CLI_INDIVIDUAL_COUNT as f64 / elapsed.as_secs_f64()
        );
        eprintln!(
            "  Hit rate:          {}/{} ({:.1}%)",
            cli_ind_hits,
            CLI_INDIVIDUAL_COUNT,
            cli_ind_hits as f64 / CLI_INDIVIDUAL_COUNT as f64 * 100.0
        );
        eprintln!();
    }

    // ── CLI: batch mode ─────────────────────────────────────────────
    let mut cli_elapsed = None;
    if cli.exists() {
        // Write corpus to a temp file
        let batch_file =
            std::env::temp_dir().join(format!("misp-fb-bench-{}.txt", http_port));
        {
            let mut f = std::fs::File::create(&batch_file).unwrap();
            for val in &corpus {
                writeln!(f, "{}", val).unwrap();
            }
        }

        let socket_path = std::env::temp_dir()
            .join(format!("misp-fbd-bench-{}.sock", http_port));

        // Warm up
        let _ = Command::new(&cli)
            .args(["--socket", &socket_path.display().to_string()])
            .args(["check", "8.8.8.8"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let start = Instant::now();
        let output = Command::new(&cli)
            .args(["--socket", &socket_path.display().to_string()])
            .args(["-f", "csv"])
            .args(["check", "--batch", &batch_file.display().to_string()])
            .output()
            .expect("Failed to run misp-fb");
        let elapsed = start.elapsed();
        cli_elapsed = Some(elapsed);

        let stdout = String::from_utf8_lossy(&output.stdout);
        let cli_total_lines = stdout.lines().count();
        let cli_hits = stdout
            .lines()
            .filter(|l| l.contains(",true,"))
            .count();
        let cli_miss_lines = stdout
            .lines()
            .filter(|l| l.contains(",false,"))
            .count();

        eprintln!("  ── CLI: misp-fb check --batch (10k values, CSV output) ──");
        eprintln!("  Total time:       {:?}", elapsed);
        eprintln!(
            "  Per value (avg):   {:?}",
            elapsed / corpus.len() as u32
        );
        eprintln!(
            "  Values/sec:        {:.0}",
            corpus.len() as f64 / elapsed.as_secs_f64()
        );
        eprintln!(
            "  Output lines:      {} ({} hit lines, {} miss lines)",
            cli_total_lines, cli_hits, cli_miss_lines
        );
        eprintln!();

        let _ = std::fs::remove_file(&batch_file);

        assert!(
            output.status.success(),
            "CLI exited with non-zero status: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        eprintln!(
            "  ── CLI: SKIPPED (binary not found at {}) ──",
            cli.display()
        );
        eprintln!("  Build with: cargo build --release --package misp-fb");
        eprintln!();
    }

    // ── Summary ─────────────────────────────────────────────────────
    eprintln!("  ── Summary ──");
    eprintln!(
        "  HTTP individual:  {:>10?}  ({:.0} req/s)",
        http_individual_elapsed,
        corpus.len() as f64 / http_individual_elapsed.as_secs_f64()
    );
    eprintln!(
        "  HTTP batch:       {:>10?}  ({:.0} val/s)",
        http_batch_elapsed,
        corpus.len() as f64 / http_batch_elapsed.as_secs_f64()
    );
    if let Some(elapsed) = cli_individual_elapsed {
        eprintln!(
            "  CLI individual:   {:>10?}  ({:.0} inv/s, {} samples)",
            elapsed,
            CLI_INDIVIDUAL_COUNT as f64 / elapsed.as_secs_f64(),
            CLI_INDIVIDUAL_COUNT
        );
    }
    if let Some(elapsed) = cli_elapsed {
        eprintln!(
            "  CLI batch:        {:>10?}  ({:.0} val/s)",
            elapsed,
            corpus.len() as f64 / elapsed.as_secs_f64()
        );
    }
    eprintln!();

    // Sanity: hit rate should be consistent across all methods
    assert_eq!(
        http_hits, batch_hits,
        "Hit count mismatch between individual ({}) and batch ({}) HTTP",
        http_hits, batch_hits
    );
}
