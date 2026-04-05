use std::sync::Arc;

use misp_fb_core::config::Config;
use misp_fb_core::engine::MatchEngine;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<RwLock<MatchEngine>>,
    pub config: Config,
}

impl AppState {
    pub fn new(engine: MatchEngine, config: Config) -> Self {
        Self {
            engine: Arc::new(RwLock::new(engine)),
            config,
        }
    }
}
