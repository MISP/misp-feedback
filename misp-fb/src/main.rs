mod client;
mod configure;
mod daemon;

use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use misp_fb_core::protocol::{
    BatchLookupResponse, HealthResponse, ListsResponse, LookupResponse,
};

use crate::client::DaemonClient;

#[derive(Parser)]
#[command(name = "misp-fb", about = "MISP Feedback CLI — check values against warninglists")]
struct Cli {
    /// Path to the daemon Unix socket
    #[arg(short, long, default_value = "/tmp/misp-fbd.sock")]
    socket: PathBuf,

    /// Path to daemon config file (used when auto-starting misp-fbd)
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Output format
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check one or more values against warninglists
    Check {
        /// Values to check (omit to read from stdin)
        values: Vec<String>,

        /// Read values from a file (one per line, use - for stdin)
        #[arg(short, long)]
        batch: Option<String>,

        /// Only match against false-positive warninglists (exclude known-identifier lists)
        #[arg(long)]
        false_positives_only: bool,
    },
    /// List all loaded warninglists
    Lists,
    /// Check daemon health
    Health,
    /// Interactively generate a config.toml file
    Config {
        /// Output path for the config file
        #[arg(short, long, default_value = "config.toml")]
        output: PathBuf,

        /// Path to warninglists directory (for listing available lists)
        #[arg(short, long, default_value = "./misp-warninglists/lists")]
        warninglists_path: PathBuf,
    },
}

#[derive(Clone, ValueEnum)]
enum OutputFormat {
    Table,
    Json,
    Csv,
}

#[tokio::main]
async fn main() -> Result<()> {

    let cli = Cli::parse();
    let client = DaemonClient::new(&cli.socket);

    match cli.command {
        Command::Config {
            output,
            warninglists_path,
        } => {
            return configure::run(&output, &warninglists_path);
        }
        _ => {}
    }

    // Ensure the daemon is running before any command that needs it
    daemon::ensure_running(&cli.socket, &cli.config).await?;

    match cli.command {
        Command::Config { .. } => unreachable!(),
        Command::Health => {
            let resp: HealthResponse = client.get("/health").await?;
            match cli.format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                _ => {
                    println!("Status: {}", resp.status);
                    println!("Lists loaded: {}", resp.lists_loaded);
                }
            }
        }
        Command::Lists => {
            let resp: ListsResponse = client.get("/lists").await?;
            match cli.format {
                OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&resp)?),
                OutputFormat::Csv => {
                    println!("slug,name,type,entries,matching_attributes");
                    for l in &resp.lists {
                        println!(
                            "{},{:?},{:?},{},\"{}\"",
                            l.slug,
                            l.name,
                            l.list_type,
                            l.entry_count,
                            l.matching_attributes.join(";")
                        );
                    }
                }
                OutputFormat::Table => {
                    println!(
                        "{:<40} {:<10} {:>8}  {}",
                        "SLUG", "TYPE", "ENTRIES", "NAME"
                    );
                    println!("{}", "-".repeat(100));
                    for l in &resp.lists {
                        println!(
                            "{:<40} {:<10} {:>8}  {}",
                            l.slug,
                            format!("{:?}", l.list_type).to_lowercase(),
                            l.entry_count,
                            l.name
                        );
                    }
                    println!("{}", "-".repeat(100));
                    println!("{} warninglists loaded", resp.count);
                }
            }
        }
        Command::Check { values, batch, false_positives_only } => {
            let values = collect_values(values, batch)?;
            if values.is_empty() {
                bail!("No values to check. Provide values as arguments, via --batch, or pipe to stdin.");
            }

            if values.len() == 1 {
                let resp: LookupResponse = client
                    .post("/lookup", &serde_json::json!({
                        "value": &values[0],
                        "false_positives_only": false_positives_only,
                    }))
                    .await?;
                print_lookup(&resp, &cli.format);
            } else {
                let resp: BatchLookupResponse = client
                    .post("/lookup/batch", &serde_json::json!({
                        "values": &values,
                        "false_positives_only": false_positives_only,
                    }))
                    .await?;
                for (i, result) in resp.results.iter().enumerate() {
                    if i > 0 && matches!(cli.format, OutputFormat::Table) {
                        println!();
                    }
                    print_lookup(result, &cli.format);
                }
            }
        }
    }

    Ok(())
}

fn collect_values(args: Vec<String>, batch: Option<String>) -> Result<Vec<String>> {
    if let Some(batch_source) = batch {
        let reader: Box<dyn BufRead> = if batch_source == "-" {
            Box::new(io::stdin().lock())
        } else {
            let file = std::fs::File::open(&batch_source)
                .with_context(|| format!("Failed to open {batch_source}"))?;
            Box::new(io::BufReader::new(file))
        };
        let values: Vec<String> = reader
            .lines()
            .filter_map(|l| l.ok())
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        return Ok(values);
    }

    if !args.is_empty() {
        return Ok(args);
    }

    // If stdin is not a terminal, read from it
    if io::stdin().is_terminal() {
        return Ok(Vec::new());
    }

    let values: Vec<String> = io::stdin()
        .lock()
        .lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(values)
}

fn print_lookup(resp: &LookupResponse, format: &OutputFormat) {
    match format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(resp).unwrap());
        }
        OutputFormat::Csv => {
            if resp.matches.is_empty() {
                println!("{},false,,", resp.value);
            } else {
                for m in &resp.matches {
                    println!(
                        "{},true,{},{}",
                        resp.value, m.slug, m.name
                    );
                }
            }
        }
        OutputFormat::Table => {
            if resp.matches.is_empty() {
                println!("{}: no matches", resp.value);
            } else {
                println!("{}: {} match(es)", resp.value, resp.matches.len());
                for m in &resp.matches {
                    println!("  - {} ({})", m.slug, m.name);
                }
            }
        }
    }
}
