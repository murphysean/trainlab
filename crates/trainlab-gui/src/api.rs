//! REST API routes and handlers for `trainlab-gui`.
//!
//! Provides JSON HTTP REST endpoints for remote control, web dashboards,
//! and script integrations alongside the MCP server.

use axum::extract::{Json, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};

use crate::mcp;
use crate::profile;
use crate::session::SharedSession;
use trainlab_core::protocol::{Request, Response};

/// Application state shared across all REST API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub session: SharedSession,
    pub egui_ctx: Option<eframe::egui::Context>,
}

impl ApiState {
    fn request_repaint(&self) {
        if let Some(ctx) = &self.egui_ctx {
            ctx.request_repaint();
        }
    }
}

const INDEX_HTML: &str = include_str!("web/index.html");

async fn serve_dashboard() -> axum::response::Html<&'static str> {
    axum::response::Html(INDEX_HTML)
}

/// Create the axum Router for `/api` REST endpoints.
pub fn router(session: SharedSession, egui_ctx: Option<eframe::egui::Context>) -> Router {
    let state = ApiState { session, egui_ctx };

    Router::new()
        .route("/status", get(get_status))
        .route("/cheats", get(get_cheats))
        .route("/cheats/toggle", post(toggle_cheat))
        .route("/cheats/apply", post(apply_cheat))
        .route("/profiles", get(get_profiles))
        .route("/profiles/load", post(load_profile))
        .route("/markers", get(get_markers).post(set_marker))
        .route("/read", post(read_memory))
        .route("/write", post(write_memory))
        .route("/scan/first", post(first_scan))
        .route("/scan/refine", post(refine_scan))
        .route("/scan/matches", get(get_scan_matches))
        .route("/window", post(window_command))
        .route("/apps", get(get_tracked_apps))
        .route("/apps/launch", post(launch_app_handler))
        .route("/events", get(sse_events_handler))
        .with_state(state)
}

pub fn dashboard_router() -> Router {
    Router::new()
        .route("/", get(serve_dashboard))
        .route("/index.html", get(serve_dashboard))
}

// --- Data Schemas ---

#[derive(Serialize)]
pub struct StatusResponse {
    pub connected: bool,
    pub game_name: String,
    pub game_pid: Option<u32>,
    pub inject_version: Option<String>,
}

#[derive(Serialize)]
pub struct CheatDto {
    pub id: u64,
    pub label: String,
    pub kind: String,
    pub enabled: Option<bool>,
    pub value: Option<String>,
    pub hotkey: Option<String>,
}

#[derive(Deserialize)]
pub struct ToggleCheatReq {
    pub cheat_id: u64,
    pub enabled: bool,
}

#[derive(Deserialize)]
pub struct ApplyCheatReq {
    pub cheat_id: u64,
    pub value: String,
}

#[derive(Deserialize)]
pub struct LoadProfileReq {
    pub name: String,
}

#[derive(Serialize)]
pub struct MarkerDto {
    pub name: String,
    pub address: String,
    pub address_hex: String,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub struct SetMarkerReq {
    pub name: String,
    pub address: String,
    pub note: Option<String>,
}

#[derive(Deserialize)]
pub struct ReadReq {
    pub address: String,
    pub len: Option<usize>,
    pub value_type: Option<String>,
}

#[derive(Serialize)]
pub struct ReadResp {
    pub address: String,
    pub address_hex: String,
    pub value: Option<String>,
    pub hex: String,
    pub bytes_read: usize,
}

#[derive(Deserialize)]
pub struct WriteReq {
    pub address: String,
    pub value: String,
    pub value_type: Option<String>,
}

#[derive(Deserialize)]
pub struct WindowReq {
    pub command: String, // "show" or "hide"
}

#[derive(Deserialize)]
pub struct LaunchAppReq {
    pub path: String,
    pub args: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct FirstScanReq {
    pub value: String,
    pub value_type: String,
    pub mode: Option<String>, // "exact" or "range"
    pub value_max: Option<String>,
}

#[derive(Deserialize)]
pub struct RefineScanReq {
    pub mode: String, // "exact", "range", "changed", "unchanged", "increased", "decreased"
    pub value: Option<String>,
    pub value_max: Option<String>,
}

#[derive(Serialize)]
pub struct ScanMatchDto {
    pub address: String,
    pub address_hex: String,
    pub value: f64,
}

#[derive(Serialize)]
pub struct ScanResp {
    pub matches_count: usize,
    pub value_type: String,
}

#[derive(Serialize)]
pub struct ApiError {
    pub error: String,
}

fn err(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: msg.into() }))
}

// --- Handlers ---

async fn get_status(State(state): State<ApiState>) -> Json<StatusResponse> {
    let s = state.session.lock().unwrap();
    Json(StatusResponse {
        connected: s.connected(),
        game_name: s.game_name().to_string(),
        game_pid: s.game_pid(),
        inject_version: s.inject_version().map(String::from),
    })
}

async fn get_cheats(State(state): State<ApiState>) -> Json<Vec<CheatDto>> {
    let s = state.session.lock().unwrap();
    let cheats = s.list_cheats().into_iter().map(|c| {
        let (kind_str, enabled, val) = match &c.kind {
            crate::session::CheatKind::Toggle { enabled, .. } => ("toggle".to_string(), Some(*enabled), None),
            crate::session::CheatKind::Button { .. } => ("button".to_string(), None, None),
            crate::session::CheatKind::Value { value_type, .. } => ("value".to_string(), None, Some(format!("{value_type:?}"))),
        };
        CheatDto {
            id: c.id,
            label: c.label.clone(),
            kind: kind_str,
            enabled,
            value: val,
            hotkey: c.hotkey.clone(),
        }
    }).collect();
    Json(cheats)
}

async fn toggle_cheat(
    State(state): State<ApiState>,
    Json(req): Json<ToggleCheatReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    mcp_srv.set_cheat_toggle(rmcp::handler::server::wrapper::Parameters(mcp::SetCheatToggleArgs {
        id: req.cheat_id,
        enabled: req.enabled,
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "cheat_id": req.cheat_id, "enabled": req.enabled })))
}

async fn apply_cheat(
    State(state): State<ApiState>,
    Json(req): Json<ApplyCheatReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    mcp_srv.set_cheat_value(rmcp::handler::server::wrapper::Parameters(mcp::SetCheatValueArgs {
        id: req.cheat_id,
        value: req.value.clone(),
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "cheat_id": req.cheat_id, "value": req.value })))
}

async fn get_profiles() -> Json<Vec<profile::GameProfile>> {
    let profiles = profile::discover_profiles();
    let list = profiles.into_iter().map(|(_, p)| p).collect();
    Json(list)
}

async fn load_profile(
    State(state): State<ApiState>,
    Json(req): Json<LoadProfileReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let session = state.session.clone();
    let egui_ctx = state.egui_ctx.clone();
    let name = req.name.clone();

    // Load profile runs AOB scans, installs code caves, and may sleep (Wait commands).
    // Run on a blocking thread so we don't starve the Axum async runtime.
    let res = tokio::task::spawn_blocking(move || {
        let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(session, egui_ctx);
        mcp_srv.load_profile_by_name(&name, true)
    })
    .await
    .map_err(|e| err(format!("profile load task panicked: {e}")))?
    .map_err(|e| err(e))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "profile": req.name, "result": res })))
}

async fn get_markers(State(state): State<ApiState>) -> Json<Vec<MarkerDto>> {
    let s = state.session.lock().unwrap();
    let markers = s.list_markers().into_iter().map(|m| {
        MarkerDto {
            name: m.label.clone(),
            address: format!("{:#x}", m.address),
            address_hex: format!("{:#x}", m.address),
            note: m.note.clone(),
        }
    }).collect();
    Json(markers)
}

async fn set_marker(
    State(state): State<ApiState>,
    Json(req): Json<SetMarkerReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    mcp_srv.set_marker(rmcp::handler::server::wrapper::Parameters(mcp::SetMarkerArgs {
        label: req.name.clone(),
        address: req.address.clone(),
        note: req.note.clone(),
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "name": req.name, "address": req.address })))
}

async fn read_memory(
    State(state): State<ApiState>,
    Json(req): Json<ReadReq>,
) -> Result<Json<ReadResp>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    let parsed_addr = mcp::parse_addr_expr(&state.session, &req.address).map_err(|e| err(format!("{e:?}")))?;
    
    let res = mcp_srv.read(rmcp::handler::server::wrapper::Parameters(mcp::ReadArgs {
        address: req.address.clone(),
        len: req.len,
        value_type: req.value_type.clone(),
    })).map_err(|e| err(e.message))?;

    let text_block = match &res.content.get(0) {
        Some(rmcp::model::ContentBlock::Text(t)) => t.text.clone(),
        _ => "".into(),
    };

    Ok(Json(ReadResp {
        address: req.address,
        address_hex: format!("{parsed_addr:#x}"),
        value: req.value_type.map(|_| text_block.clone()),
        hex: text_block,
        bytes_read: req.len.unwrap_or(4),
    }))
}

async fn write_memory(
    State(state): State<ApiState>,
    Json(req): Json<WriteReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    mcp_srv.write(rmcp::handler::server::wrapper::Parameters(mcp::WriteArgs {
        address: req.address.clone(),
        data: None,
        value: Some(req.value.clone()),
        value_type: req.value_type,
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "address": req.address, "value": req.value })))
}

async fn first_scan(
    State(state): State<ApiState>,
    Json(req): Json<FirstScanReq>,
) -> Result<Json<ScanResp>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    let val_f64 = req.value.parse::<f64>().map_err(|_| err("invalid scan value float"))?;
    let val_max_f64 = req.value_max.as_deref().and_then(|v| v.parse::<f64>().ok());

    let _ = mcp_srv.scan(rmcp::handler::server::wrapper::Parameters(mcp::ScanArgs {
        value: val_f64,
        value_type: req.value_type.clone(),
        max: val_max_f64,
        alignment: None,
    })).map_err(|e| err(e.message))?;

    let count = {
        let s = state.session.lock().unwrap();
        s.scan().map(|sc| sc.len()).unwrap_or(0)
    };

    state.request_repaint();
    Ok(Json(ScanResp {
        matches_count: count,
        value_type: req.value_type,
    }))
}

async fn refine_scan(
    State(state): State<ApiState>,
    Json(req): Json<RefineScanReq>,
) -> Result<Json<ScanResp>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    let val_f64 = req.value.as_deref().and_then(|v| v.parse::<f64>().ok());
    let val_max_f64 = req.value_max.as_deref().and_then(|v| v.parse::<f64>().ok());

    let _ = mcp_srv.next(rmcp::handler::server::wrapper::Parameters(mcp::NextArgs {
        op: req.mode,
        value: val_f64,
        max: val_max_f64,
    })).map_err(|e| err(e.message))?;

    let (count, vt_str) = {
        let s = state.session.lock().unwrap();
        if let Some(sc) = s.scan() {
            (sc.len(), format!("{:?}", sc.value_type()))
        } else {
            (0, "unknown".into())
        }
    };

    state.request_repaint();
    Ok(Json(ScanResp {
        matches_count: count,
        value_type: vt_str,
    }))
}

async fn get_scan_matches(State(state): State<ApiState>) -> Json<Vec<ScanMatchDto>> {
    let s = state.session.lock().unwrap();
    let matches = if let Some(sc) = s.scan() {
        sc.matches().iter().take(100).map(|(addr, val)| {
            ScanMatchDto {
                address: format!("{addr:#x}"),
                address_hex: format!("{addr:#x}"),
                value: *val,
            }
        }).collect()
    } else {
        Vec::new()
    };
    Json(matches)
}

async fn window_command(
    State(state): State<ApiState>,
    Json(req): Json<WindowReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let cmd = req.command.trim().to_lowercase();
    if cmd != "show" && cmd != "hide" {
        return Err(err("invalid window command; expected 'show' or 'hide'"));
    }
    {
        let mut s = state.session.lock().unwrap();
        s.request_window_cmd(&cmd);
    }
    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "command": cmd })))
}

async fn get_tracked_apps(State(state): State<ApiState>) -> Json<Vec<crate::session::DiscoveredApp>> {
    let s = state.session.lock().unwrap();
    Json(s.list_tracked_apps())
}

async fn launch_app_handler(
    State(state): State<ApiState>,
    Json(req): Json<LaunchAppReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let args = req.args.unwrap_or_default();
    let pid = {
        let mut s = state.session.lock().unwrap();
        s.launch_application(&req.path, &args).map_err(|e| err(e))?
    };
    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "path": req.path, "pid": pid })))
}

use axum::response::sse::{Event, Sse};
use futures_util::stream::Stream;
use std::convert::Infallible;

async fn sse_events_handler(
    State(state): State<ApiState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut rx = {
        let s = state.session.lock().unwrap();
        s.event_bus().subscribe()
    };

    let stream = async_stream::stream! {
        while let Ok(evt) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&evt) {
                yield Ok(Event::default().data(json));
            }
        }
    };

    Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}
