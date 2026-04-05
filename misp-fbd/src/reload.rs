use std::time::Duration;

use anyhow::{Context, Result};
use misp_fb_core::engine::MatchEngine;
use misp_fb_core::loader::load_warninglists;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::state::AppState;

/// Start watching the warninglists directory for changes.
/// Returns the watcher handle (drop it to stop watching).
pub fn start_watcher(state: AppState) -> Result<RecommendedWatcher> {
    let (tx, rx) = mpsc::channel::<()>(1);

    let mut watcher =
        notify::recommended_watcher(move |res: std::result::Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    if matches!(
                        event.kind,
                        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
                    ) {
                        let _ = tx.try_send(());
                    }
                }
                Err(e) => warn!(error = %e, "File watcher error"),
            }
        })
        .context("Failed to create file watcher")?;

    watcher
        .watch(
            &state.config.daemon.warninglists_path,
            RecursiveMode::Recursive,
        )
        .with_context(|| {
            format!(
                "Failed to watch {}",
                state.config.daemon.warninglists_path.display()
            )
        })?;

    info!(
        path = %state.config.daemon.warninglists_path.display(),
        "Watching warninglists directory for changes"
    );

    tokio::spawn(reload_loop(state, rx));

    Ok(watcher)
}

async fn reload_loop(state: AppState, mut rx: mpsc::Receiver<()>) {
    while rx.recv().await.is_some() {
        // Debounce: drain any additional events that arrive within 500ms
        tokio::time::sleep(Duration::from_millis(500)).await;
        while rx.try_recv().is_ok() {}

        info!("Warninglists changed, reloading...");

        let config = state.config.clone();
        let result = tokio::task::spawn_blocking(move || {
            let filter = config.warninglists.build_filter()?;
            let raw_lists = load_warninglists(&config.daemon.warninglists_path, &*filter)?;
            Ok::<MatchEngine, misp_fb_core::error::Error>(MatchEngine::build(raw_lists))
        })
        .await;

        match result {
            Ok(Ok(new_engine)) => {
                let list_count = new_engine.lists().len();
                let mut engine = state.engine.write().await;
                *engine = new_engine;
                info!(lists = list_count, "Engine reloaded successfully");
            }
            Ok(Err(e)) => {
                error!(error = %e, "Failed to reload warninglists, keeping previous engine");
            }
            Err(e) => {
                error!(error = %e, "Reload task panicked");
            }
        }
    }
}
