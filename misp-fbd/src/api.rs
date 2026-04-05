use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use misp_fb_core::engine::MatchEngine;
use misp_fb_core::model::Category;
use misp_fb_core::protocol::{
    BatchLookupRequest, BatchLookupResponse, HealthResponse, ListsResponse, LookupRequest,
    LookupResponse, MatchInfo,
};
use tokio::sync::RwLock;

type SharedEngine = Arc<RwLock<MatchEngine>>;

pub fn router(engine: SharedEngine) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/lists", get(list_warninglists))
        .route("/lookup", post(lookup))
        .route("/lookup/batch", post(lookup_batch))
        .route("/openapi.json", get(openapi_spec))
        .route("/docs", get(swagger_ui))
        .with_state(engine)
}

async fn health(State(engine): State<SharedEngine>) -> Json<HealthResponse> {
    let engine = engine.read().await;
    Json(HealthResponse {
        status: "ok".into(),
        lists_loaded: engine.lists().len(),
    })
}

async fn list_warninglists(State(engine): State<SharedEngine>) -> Json<ListsResponse> {
    let engine = engine.read().await;
    let lists = engine.lists().to_vec();
    Json(ListsResponse {
        count: lists.len(),
        lists,
    })
}

fn do_lookup(engine: &MatchEngine, value: &str, false_positives_only: bool) -> Vec<MatchInfo> {
    let results = if false_positives_only {
        engine.lookup_by_category(value, Category::FalsePositive)
    } else {
        engine.lookup(value)
    };
    results.into_iter().map(MatchInfo::from).collect()
}

async fn lookup(
    State(engine): State<SharedEngine>,
    Json(req): Json<LookupRequest>,
) -> Json<LookupResponse> {
    let engine = engine.read().await;
    let matches = do_lookup(&engine, &req.value, req.false_positives_only);
    Json(LookupResponse {
        value: req.value,
        matched: !matches.is_empty(),
        matches,
    })
}

async fn lookup_batch(
    State(engine): State<SharedEngine>,
    Json(req): Json<BatchLookupRequest>,
) -> Result<Json<BatchLookupResponse>, StatusCode> {
    if req.values.len() > 10_000 {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let engine = engine.read().await;
    let results = req
        .values
        .into_iter()
        .map(|value| {
            let matches = do_lookup(&engine, &value, req.false_positives_only);
            LookupResponse {
                matched: !matches.is_empty(),
                value,
                matches,
            }
        })
        .collect();

    Ok(Json(BatchLookupResponse { results }))
}

async fn openapi_spec() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        include_str!("../openapi.json"),
    )
}

async fn swagger_ui() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/html")],
        include_str!("../swagger-ui.html"),
    )
}
