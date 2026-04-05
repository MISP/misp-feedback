mod api;
mod reload;
mod state;

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use misp_fb_core::config::Config;
use misp_fb_core::engine::MatchEngine;
use misp_fb_core::loader::load_warninglists;
use tokio::net::UnixListener;
use tokio::signal;
use tracing::{error, info};

use crate::state::AppState;

#[derive(Parser)]
#[command(name = "misp-fbd", about = "MISP Feedback daemon")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    let config = Config::load(&cli.config)
        .with_context(|| format!("Failed to load config from {}", cli.config.display()))?;

    info!(config_path = %cli.config.display(), "Loaded configuration");

    let engine = build_engine(&config)?;
    let list_count = engine.lists().len();
    let state = AppState::new(engine, config.clone());

    info!(lists = list_count, "Match engine ready");

    let app = api::router(Arc::clone(&state.engine));

    // Start the file watcher for hot-reload
    let watcher_handle = reload::start_watcher(state.clone())?;

    // Start listeners
    let socket_path = config.daemon.socket_path.clone();
    let http_bind = config.daemon.http_bind.clone();

    // Clean up stale socket file
    if socket_path.exists() {
        std::fs::remove_file(&socket_path)
            .with_context(|| format!("Failed to remove stale socket {}", socket_path.display()))?;
    }

    let uds_listener = UnixListener::bind(&socket_path)
        .with_context(|| format!("Failed to bind Unix socket at {}", socket_path.display()))?;

    info!(path = %socket_path.display(), "Unix socket listener started");

    let uds_app = app.clone();
    let uds_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(uds_listener, uds_app).await {
            error!(error = %e, "Unix socket server error");
        }
    });

    let http_handle = if let Some(ref bind_addr) = http_bind {
        let tcp_listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("Failed to bind HTTP on {bind_addr}"))?;
        info!(bind = %bind_addr, "HTTP listener started");
        let http_app = app.clone();
        Some(tokio::spawn(async move {
            if let Err(e) = axum::serve(tcp_listener, http_app).await {
                error!(error = %e, "HTTP server error");
            }
        }))
    } else {
        None
    };

    info!("misp-fbd is ready");

    // Wait for shutdown signal
    shutdown_signal().await;

    info!("Shutting down...");

    // Abort server tasks
    uds_handle.abort();
    if let Some(h) = http_handle {
        h.abort();
    }
    drop(watcher_handle);

    // Clean up socket file
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    info!("Shutdown complete");
    Ok(())
}

fn build_engine(config: &Config) -> Result<MatchEngine> {
    let filter = config
        .warninglists
        .build_filter()
        .context("Invalid warninglists filter config")?;
    let raw_lists = load_warninglists(&config.daemon.warninglists_path, &*filter)
        .context("Failed to load warninglists")?;
    Ok(MatchEngine::build(raw_lists))
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => info!("Received SIGINT"),
        _ = terminate => info!("Received SIGTERM"),
    }
}
