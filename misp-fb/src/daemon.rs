use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

/// Ensure the daemon is running and reachable on the given socket.
/// If it's not, attempt to start it automatically.
pub async fn ensure_running(socket_path: &Path, config_path: &Path) -> Result<()> {
    // Quick check: can we connect to the socket?
    if tokio::net::UnixStream::connect(socket_path).await.is_ok() {
        return Ok(());
    }

    // Daemon isn't reachable — try to start it
    let daemon_bin = find_daemon_binary()?;
    let config = find_config(config_path)?;

    eprintln!(
        "Daemon not running, starting misp-fbd (config: {})...",
        config.display()
    );

    // Start daemon as a detached background process
    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.arg("--config")
        .arg(&config)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    // Detach from the CLI process so the daemon outlives us
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    cmd.spawn().with_context(|| {
        format!(
            "Failed to start daemon: {}",
            daemon_bin.display()
        )
    })?;

    // Wait for the daemon to become ready
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if Instant::now() > deadline {
            bail!(
                "Daemon failed to start within 30 seconds.\n\
                 Check the daemon logs: RUST_LOG=debug misp-fbd --config {}",
                config.display()
            );
        }

        if tokio::net::UnixStream::connect(socket_path).await.is_ok() {
            eprintln!("Daemon started successfully.");
            return Ok(());
        }

        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Find the config file. Searches:
/// 1. The path as given (absolute or relative to cwd)
/// 2. Next to the current executable
/// 3. In /etc/misp-feedback/
fn find_config(config_path: &Path) -> Result<std::path::PathBuf> {
    // Explicit path exists — use it
    if config_path.exists() {
        return Ok(config_path.to_path_buf());
    }

    let filename = config_path
        .file_name()
        .unwrap_or(std::ffi::OsStr::new("config.toml"));

    // Next to our own binary (e.g. running from target/release/)
    if let Ok(self_path) = std::env::current_exe() {
        if let Some(bin_dir) = self_path.parent() {
            // Check sibling of binary
            let candidate = bin_dir.join(filename);
            if candidate.exists() {
                return Ok(candidate);
            }
            // Check project root (two levels up from target/release/)
            if let Some(parent) = bin_dir.parent().and_then(|p| p.parent()) {
                let candidate = parent.join(filename);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    // System-wide location
    let system = std::path::PathBuf::from("/etc/misp-feedback").join(filename);
    if system.exists() {
        return Ok(system);
    }

    bail!(
        "Daemon is not running and config file not found.\n\
         Searched:\n\
         \x20 - {}\n\
         \x20 - next to the misp-fb binary\n\
         \x20 - /etc/misp-feedback/\n\n\
         Start the daemon manually with: misp-fbd --config <path>\n\
         Or generate a config with: misp-fb config",
        config_path.display()
    )
}

/// Find the misp-fbd binary. Looks next to the current executable first,
/// then falls back to PATH.
fn find_daemon_binary() -> Result<std::path::PathBuf> {
    // Check next to our own binary
    if let Ok(self_path) = std::env::current_exe() {
        let sibling = self_path.parent().unwrap().join("misp-fbd");
        if sibling.exists() {
            return Ok(sibling);
        }
    }

    // Check PATH
    if let Ok(output) = std::process::Command::new("which")
        .arg("misp-fbd")
        .output()
    {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Ok(std::path::PathBuf::from(path));
            }
        }
    }

    bail!(
        "Could not find misp-fbd binary.\n\
         Make sure it is in the same directory as misp-fb or in your PATH."
    )
}
