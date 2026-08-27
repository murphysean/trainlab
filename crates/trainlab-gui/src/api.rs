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
        .route("/cheats/run", post(run_cheat))
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
        .route("/log", get(get_activity_log))
        .route("/events", get(sse_events_handler))
        // T-120: Add confirm/reject/pending endpoints for D8 staged ops.
        .route("/pending", get(list_pending_ops))
        .route("/confirm_op", post(confirm_op_handler))
        .route("/reject_op", post(reject_op_handler))
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
pub struct RunCheatReq {
    pub cheat_id: u64,
}

#[derive(Deserialize)]
pub struct LoadProfileReq {
    pub name: String,
}

#[derive(Serialize)]
pub struct MarkerDto {
    pub name: String,
    pub address: String,
    #[serde(skip_serializing)]
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
    #[serde(skip_serializing)]
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

#[derive(Deserialize)]
pub struct OpConfirmReq {
    pub id: u64,
}

#[derive(Serialize)]
pub struct PendingOpDto {
    pub id: u64,
    pub kind: String,
    pub address: String,
    pub preview: String,
}

/// T-122: Helper for safe session locking. For handlers returning `Result`,
/// use `lock_session(&state)?`. For handlers returning `Json<T>` directly,
/// use `lock_session_or_500(&state)` which returns a 500 on poison.
fn err(msg: impl Into<String>) -> (StatusCode, Json<ApiError>) {
    (StatusCode::BAD_REQUEST, Json(ApiError { error: msg.into() }))
}

fn lock_session_or_500(state: &ApiState) -> Result<std::sync::MutexGuard<'_, crate::session::SessionState>, (StatusCode, Json<ApiError>)> {
    state.session.lock().map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(ApiError { error: "session lock poisoned".into() }))
    })
}

// --- Handlers ---

async fn get_status(State(state): State<ApiState>) -> Result<Json<StatusResponse>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
    Ok(Json(StatusResponse {
        connected: s.connected(),
        game_name: s.game_name().to_string(),
        game_pid: s.game_pid(),
        inject_version: s.inject_version().map(String::from),
    }))
}

async fn get_cheats(State(state): State<ApiState>) -> Result<Json<Vec<CheatDto>>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
    let cheats = s.list_cheats().into_iter().map(|c| {
        let (kind_str, enabled, val) = match &c.kind {
            crate::session::CheatKind::Toggle { enabled, .. } => ("toggle".to_string(), Some(*enabled), None),
            crate::session::CheatKind::Patch { enabled, .. } => ("patch".to_string(), Some(*enabled), None),
            crate::session::CheatKind::Button { .. } => ("button".to_string(), None, None),
            crate::session::CheatKind::Value { value_type, .. } => ("value".to_string(), None, Some(format!("{value_type:?}"))),
            crate::session::CheatKind::Struct { fields, .. } => ("struct".to_string(), None, Some(format!("{} field(s)", fields.len()))),
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
    Ok(Json(cheats))
}

async fn toggle_cheat(
    State(state): State<ApiState>,
    Json(req): Json<ToggleCheatReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    let result = mcp_srv.set_cheat_toggle(rmcp::handler::server::wrapper::Parameters(mcp::SetCheatToggleArgs {
        id: req.cheat_id,
        enabled: req.enabled,
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    // T-121: Return staged status with pending_id instead of claiming it applied.
    let text = result.content.into_iter().find_map(|b| match b {
        rmcp::model::ContentBlock::Text(t) => Some(t.text),
        _ => None,
    }).unwrap_or_default();
    let pending_id = text.split("pending id ").nth(1).and_then(|s| s.split(')').next()).and_then(|s| s.parse::<u64>().ok());
    if let Some(pid) = pending_id {
        Ok(Json(serde_json::json!({ "status": "staged", "pending_id": pid, "cheat_id": req.cheat_id, "enabled": req.enabled })))
    } else {
        Ok(Json(serde_json::json!({ "status": "ok", "cheat_id": req.cheat_id, "enabled": req.enabled, "message": text })))
    }
}

async fn apply_cheat(
    State(state): State<ApiState>,
    Json(req): Json<ApplyCheatReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    let result = mcp_srv.set_cheat_value(rmcp::handler::server::wrapper::Parameters(mcp::SetCheatValueArgs {
        id: req.cheat_id,
        value: req.value.clone(),
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    // T-121: Return staged status with pending_id.
    let text = result.content.into_iter().find_map(|b| match b {
        rmcp::model::ContentBlock::Text(t) => Some(t.text),
        _ => None,
    }).unwrap_or_default();
    let pending_id = text.split("pending id ").nth(1).and_then(|s| s.split(')').next()).and_then(|s| s.parse::<u64>().ok());
    if let Some(pid) = pending_id {
        Ok(Json(serde_json::json!({ "status": "staged", "pending_id": pid, "cheat_id": req.cheat_id, "value": req.value })))
    } else {
        Ok(Json(serde_json::json!({ "status": "ok", "cheat_id": req.cheat_id, "value": req.value, "message": text })))
    }
}

/// `POST /api/cheats/run` — execute a Button cheat's command sequence.
///
/// For Toggle / Value cheats this is an error; those are handled by
/// `/api/cheats/toggle` and `/api/cheats/apply` respectively. Button cheats
/// run a macro sequence of profile commands (writes, cave installs, etc.) and
/// each step is logged to the session's activity log (visible in the egui
/// Activity Log panel and via SSE `activity_logged` events).
async fn run_cheat(
    State(state): State<ApiState>,
    Json(req): Json<RunCheatReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    // Resolve the cheat outside the spawn_blocking closure to give a clear
    // error before touching the thread pool.
    let commands = {
        let s = lock_session_or_500(&state)?;
        match s.get_cheat(req.cheat_id) {
            None => return Err(err(format!("no cheat with id {}", req.cheat_id))),
            Some(c) => match &c.kind {
                crate::session::CheatKind::Button { commands } => commands.clone(),
                _ => return Err(err(format!(
                    "cheat {} is not a button cheat; use /cheats/toggle or /cheats/apply",
                    req.cheat_id
                ))),
            },
        }
    };

    let label = {
        let s = lock_session_or_500(&state)?;
        s.get_cheat(req.cheat_id).map(|c| c.label.clone()).unwrap_or_default()
    };

    {
        let mut s = lock_session_or_500(&state)?;
        s.log_activity("API", format!("button '{}' triggered: running {} command(s)...", label, commands.len()));
    }

    let session = state.session.clone();

    // Run on a blocking thread — commands may contain Wait steps that sleep.
    let result = tokio::task::spawn_blocking(move || {
        mcp::execute_profile_commands(&session, &commands)
    })
    .await
    .map_err(|e| err(format!("run_cheat task panicked: {e}")))?;

    match result {
        Ok(()) => {
            {
                let mut s = lock_session_or_500(&state)?;
                s.log_activity("API", format!("button '{}' completed ok", label));
            }
            state.request_repaint();
            Ok(Json(serde_json::json!({
                "status": "ok",
                "cheat_id": req.cheat_id,
                "label": label,
            })))
        }
        Err(e) => {
            {
                let mut s = lock_session_or_500(&state)?;
                s.log_activity("API", format!("button '{}' failed: {e}", label));
            }
            state.request_repaint();
            Err(err(format!("button '{}' failed: {e}", label)))
        }
    }
}

/// `GET /api/log` — return the session activity log as a JSON array.
///
/// Returns up to the last 1000 entries (the session's in-memory cap).
/// Also available via SSE: the `/events` stream emits `activity_logged`
/// events for real-time updates.
async fn get_activity_log(State(state): State<ApiState>) -> Result<Json<Vec<String>>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
    Ok(Json(s.list_activity_log()))
}

async fn get_profiles() -> Json<Vec<profile::GameProfile>> {
    // T-164: FS I/O should be off the executor thread.
    let profiles = tokio::task::spawn_blocking(profile::discover_profiles)
        .await
        .unwrap_or_default();
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

    // Load profile from the web dashboard: auto-attaches to the game process if
    // needed, executes setup steps and init_commands, and materializes cheats and markers.
    let res = tokio::task::spawn_blocking(move || {
        let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(session, egui_ctx);
        mcp_srv.load_profile_by_name(&name, true)
    })
    .await
    .map_err(|e| err(format!("profile load task panicked: {e}")))?
    .map_err(err)?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "profile": req.name, "result": res })))
}

async fn get_markers(State(state): State<ApiState>) -> Result<Json<Vec<MarkerDto>>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
    let markers = s.list_markers().into_iter().map(|m| {
        MarkerDto {
            name: m.label.clone(),
            address: format!("{:#x}", m.address),
            address_hex: format!("{:#x}", m.address),
            note: m.note.clone(),
        }
    }).collect();
    Ok(Json(markers))
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

    let text_block = match &res.content.first() {
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
    let result = mcp_srv.write(rmcp::handler::server::wrapper::Parameters(mcp::WriteArgs {
        address: req.address.clone(),
        data: None,
        value: Some(req.value.clone()),
        value_type: req.value_type,
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    // T-121: Return staged status with pending_id.
    let text = result.content.into_iter().find_map(|b| match b {
        rmcp::model::ContentBlock::Text(t) => Some(t.text),
        _ => None,
    }).unwrap_or_default();
    let pending_id = text.split("pending id ").nth(1).and_then(|s| s.split('.').next().or_else(|| s.split(')').next())).and_then(|s| s.trim().parse::<u64>().ok());
    if let Some(pid) = pending_id {
        Ok(Json(serde_json::json!({ "status": "staged", "pending_id": pid, "address": req.address, "value": req.value })))
    } else {
        Ok(Json(serde_json::json!({ "status": "ok", "address": req.address, "value": req.value, "message": text })))
    }
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
        let s = lock_session_or_500(&state)?;
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
        let s = lock_session_or_500(&state)?;
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

async fn get_scan_matches(State(state): State<ApiState>) -> Result<Json<Vec<ScanMatchDto>>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
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
    Ok(Json(matches))
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
        let mut s = lock_session_or_500(&state)?;
        s.request_window_cmd(&cmd);
    }
    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "command": cmd })))
}

async fn get_tracked_apps(State(state): State<ApiState>) -> Result<Json<Vec<crate::session::DiscoveredApp>>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
    Ok(Json(s.list_tracked_apps()))
}

async fn launch_app_handler(
    State(state): State<ApiState>,
    Json(req): Json<LaunchAppReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let args = req.args.unwrap_or_default();
    let pid = {
        let mut s = lock_session_or_500(&state)?;
        s.launch_application(&req.path, &args).map_err(err)?
    };
    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "path": req.path, "pid": pid })))
}

// --- T-120: Pending op handlers ---

/// `GET /api/pending` — list all staged (pending) mutations awaiting confirmation.
async fn list_pending_ops(State(state): State<ApiState>) -> Result<Json<Vec<PendingOpDto>>, (StatusCode, Json<ApiError>)> {
    let s = lock_session_or_500(&state)?;
    let pending: Vec<PendingOpDto> = s.list_pending().iter().map(|p| {
        PendingOpDto {
            id: p.id,
            kind: p.kind.kind_text().to_string(),
            address: format!("{:#x}", p.address),
            preview: p.preview.clone(),
        }
    }).collect();
    Ok(Json(pending))
}

/// `POST /api/confirm_op` — apply a staged mutation by id.
async fn confirm_op_handler(
    State(state): State<ApiState>,
    Json(req): Json<OpConfirmReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    mcp_srv.confirm_op(rmcp::handler::server::wrapper::Parameters(mcp::OpConfirmArgs {
        id: req.id,
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "id": req.id })))
}

/// `POST /api/reject_op` — discard a staged mutation by id.
async fn reject_op_handler(
    State(state): State<ApiState>,
    Json(req): Json<OpConfirmReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ApiError>)> {
    let mcp_srv = mcp::TrainlabMcpServer::with_session_and_ctx(state.session.clone(), state.egui_ctx.clone());
    mcp_srv.reject_op(rmcp::handler::server::wrapper::Parameters(mcp::OpConfirmArgs {
        id: req.id,
    })).map_err(|e| err(e.message))?;

    state.request_repaint();
    Ok(Json(serde_json::json!({ "status": "ok", "id": req.id })))
}

use axum::response::sse::{Event, Sse};
use futures_util::stream::Stream;
use std::convert::Infallible;

async fn sse_events_handler(
    State(state): State<ApiState>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, (StatusCode, Json<ApiError>)> {
    let mut rx = {
        let s = lock_session_or_500(&state)?;
        s.event_bus().subscribe()
    };

    let stream = async_stream::stream! {
        while let Ok(evt) = rx.recv().await {
            if let Ok(json) = serde_json::to_string(&evt) {
                yield Ok(Event::default().data(json));
            }
        }
    };

    Ok(Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default()))
}