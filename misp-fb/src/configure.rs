use std::path::Path;

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, MultiSelect, Select};

pub fn run(output: &Path, warninglists_path: &Path) -> Result<()> {
    println!("MISP Feedback configuration\n");

    // --- Socket path ---
    let socket_path: String = Input::new()
        .with_prompt("Unix socket path")
        .default("/tmp/misp-fbd.sock".into())
        .interact_text()?;

    // --- HTTP listener ---
    let enable_http = Confirm::new()
        .with_prompt("Enable HTTP listener?")
        .default(false)
        .interact()?;

    let http_bind = if enable_http {
        let addr: String = Input::new()
            .with_prompt("HTTP bind address")
            .default("127.0.0.1:3000".into())
            .interact_text()?;
        Some(addr)
    } else {
        None
    };

    // --- Warninglists path ---
    let wl_path: String = Input::new()
        .with_prompt("Warninglists directory")
        .default(warninglists_path.display().to_string())
        .interact_text()?;

    // --- Warninglist filtering ---
    let filter_mode = Select::new()
        .with_prompt("Which warninglists to load?")
        .items(&["All lists", "Only selected lists", "All except selected lists"])
        .default(0)
        .interact()?;

    let lists_config = if filter_mode == 0 {
        Vec::new()
    } else {
        let resolve_path = if Path::new(&wl_path).is_absolute() {
            std::path::PathBuf::from(&wl_path)
        } else {
            // Resolve relative to the output file's parent directory
            output
                .parent()
                .unwrap_or(Path::new("."))
                .join(&wl_path)
        };

        let available = discover_lists(&resolve_path);
        if available.is_empty() {
            println!(
                "  Warning: no warninglists found in {}",
                resolve_path.display()
            );
            println!("  You can edit the config file manually later.\n");
            Vec::new()
        } else {
            let selected = MultiSelect::new()
                .with_prompt(if filter_mode == 1 {
                    "Select lists to include (space to toggle, enter to confirm)"
                } else {
                    "Select lists to exclude (space to toggle, enter to confirm)"
                })
                .items(&available)
                .interact()?;

            if selected.is_empty() {
                println!("  No lists selected, will load all.\n");
                Vec::new()
            } else {
                selected
                    .into_iter()
                    .map(|i| {
                        let slug = available[i].clone();
                        if filter_mode == 2 {
                            format!("!{slug}")
                        } else {
                            slug
                        }
                    })
                    .collect()
            }
        }
    };

    // --- Build TOML ---
    let mut toml = String::new();
    toml.push_str("[daemon]\n");
    toml.push_str(&format!("socket_path = {:?}\n", socket_path));
    if let Some(ref addr) = http_bind {
        toml.push_str(&format!("http_bind = {:?}\n", addr));
    }
    toml.push_str(&format!("warninglists_path = {:?}\n", wl_path));
    toml.push('\n');
    toml.push_str("[warninglists]\n");
    if lists_config.is_empty() {
        toml.push_str("lists = []\n");
    } else {
        toml.push_str("lists = [\n");
        for entry in &lists_config {
            toml.push_str(&format!("    {:?},\n", entry));
        }
        toml.push_str("]\n");
    }

    // --- Confirm and write ---
    println!("\n--- Generated config ---");
    println!("{toml}");

    if output.exists() {
        let overwrite = Confirm::new()
            .with_prompt(format!("{} already exists. Overwrite?", output.display()))
            .default(false)
            .interact()?;
        if !overwrite {
            println!("Aborted.");
            return Ok(());
        }
    }

    std::fs::write(output, &toml)
        .with_context(|| format!("Failed to write {}", output.display()))?;

    println!("Config written to {}", output.display());
    Ok(())
}

fn discover_lists(lists_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(lists_dir) else {
        return Vec::new();
    };

    let mut slugs: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().map(|ft| ft.is_dir()).unwrap_or(false))
        .filter(|e| e.path().join("list.json").exists())
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();

    slugs.sort();
    slugs
}
