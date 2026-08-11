//! Live MCP driver to validate the code-cave instruction-aligned patch fix.
//!
//! Drives the running `trainlab-gui` MCP server (external, crash-safe scans)
//! + the injected DLL fast channel (poke-family: watch / cave). It runs as
//! discrete *stages* so a human can make the game tick between steps and so we
//! share the GUI's persistent session state (the scan match set survives across
//! separate invocations).
//!
//! Usage:  cargo run -p trainlab-gui --example cave_validate -- <stage>
//!
//! Stages:
//!   ping        - confirm MCP server + DLL are alive.
//!   games       - list candidate game processes (for attach).
//!   attach <game> [inject] - attach to a game: find, inject, connect.
//!   status      - report trainer/connection status.
//!   addcheat <label> value <addr> <type> [note] - add a value cheat.
//!   addcheat <label> toggle <target> [hook] [payload] - add a toggle cheat.
//!   cheats      - list cheats.
//!   setcheat <id> <value> - stage a value write for a cheat.
//!   profiles    - list cheat profiles in cheats/.
//!   loadprofile <name> [run_setup] - load a profile (run setup, materialize).
//!   saveprofile [file] - save current cheats to a profile.
//!   seed <val>  - first f32 scan (exact <val>) as a seed set.
//!   seedi <val> - first i32 scan (integer currency).
//!   seedr <min> <max> - first f32 range scan.
//!   narrow      - `next changed` after a game tick; report candidates.
//!   read <addr> - read f32 at an address (direct DLL read).
//!   write <addr> <f32> [confirm] - stage an f32 write (4 bytes).
//!   writei <addr> <i32> [confirm] - stage an i32 write (4 bytes).
//!   watch <addr>- arm watch_writes; poll to capture the writing RIP.
//!   poll        - retrieve a pending watchpoint hit.
//!   disasm <addr> - disassemble bytes at an address.
//!   dumpstruct <addr> name:type[:offset[:len]]... - read a struct as typed
//!               fields (types: i8/u8/i16/u16/i32/u32/i64/u64/f32/f64/ptr/cstr/bytes).
//!   cave <target> [hook=trampoline|override] [payload-hex] [confirm]
//!               - stage a cave install at a target.
//!   pending     - list staged (unconfirmed) mutations.
//!   confirm <id> - apply a staged mutation (human gate).
//!   reject <id> - discard a staged mutation.
//!   restore <id> - stage+apply an undo of a cave/write.
//!   clear       - clear any armed watchpoint/breakpoint.
//!
//! D8 confirmation gate: the `write`/`writei`/`cave`/`restore` stages *stage*
//! a mutation and return a pending id; they do not modify memory until you
//! pass `confirm` (or run the `confirm <id>` stage). This is deliberate — an
//! agent proposes, a human confirms.
//!
//! Each stage connects to the MCP server (for external scan ops) or the DLL
//! fast channel (for poke-family / raw reads) as appropriate.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rmcp::model::CallToolRequestParams;
use rmcp::service::ServiceExt;
use rmcp::transport::StreamableHttpClientTransport;
use rmcp::ClientHandler;

const MCP_URL: &str = "http://127.0.0.1:8123/mcp";
const DLL_PORT: u16 = 31337;

fn dll_rpc(req: &trainlab_core::protocol::Request) -> Result<trainlab_core::protocol::Response, String> {
    let addr = format!("127.0.0.1:{DLL_PORT}");
    let mut s = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    s.set_nodelay(true).ok();
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let frame = trainlab_core::protocol::encode(req).map_err(|e| format!("encode: {e}"))?;
    s.write_all(&frame).map_err(|e| format!("write: {e}"))?;
    let mut lb = [0u8; 4];
    s.read_exact(&mut lb).map_err(|e| format!("read len: {e}"))?;
    let len = u32::from_le_bytes(lb) as usize;
    let mut body = vec![0u8; len];
    s.read_exact(&mut body).map_err(|e| format!("read body: {e}"))?;
    let mut fo = Vec::with_capacity(4 + len);
    fo.extend_from_slice(&lb);
    fo.extend_from_slice(&body);
    trainlab_core::protocol::decode(&fo).map_err(|e| format!("decode: {e}"))
}

fn read_f32_dll(addr: u64) -> Option<f32> {
    match dll_rpc(&trainlab_core::protocol::Request::Read { address: addr, len: 4 }) {
        Ok(trainlab_core::protocol::Response::Read { data }) if data.len() == 4 => {
            Some(f32::from_le_bytes([data[0], data[1], data[2], data[3]]))
        }
        _ => None,
    }
}

struct Client;
impl ClientHandler for Client {}

fn extract_text(resp: &rmcp::model::CallToolResult) -> String {
    resp.content
        .iter()
        .filter_map(|b| match b {
            rmcp::model::ContentBlock::Text(t) => Some(t.text.clone()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Call a staging MCP tool (write/install_cave/undo), print its pending-op
/// response, and optionally confirm it (apply) in the same invocation.
///
/// The D8 confirmation gate is enforced by the server: the staging tool never
/// modifies memory; `confirm_op` is the only thing that applies a staged op.
async fn stage_then_confirm(
    client: &rmcp::service::RunningService<rmcp::RoleClient, Client>,
    tool: &'static str,
    tool_args: &[(&str, serde_json::Value)],
    confirm: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let r = client
        .call_tool(CallToolRequestParams::new(tool).with_arguments(args(tool_args)))
        .await?;
    let text = extract_text(&r);
    println!("{}", text);
    if confirm {
        // Parse the pending id out of the "pending id N" response.
        if let Some(n) = parse_pending_id(&text) {
            let r2 = client
                .call_tool(CallToolRequestParams::new("confirm_op").with_arguments(args(&[
                    ("id", serde_json::json!(n)),
                ])))
                .await?;
            println!("{}", extract_text(&r2));
        } else {
            println!("(no pending id found; not confirming)");
        }
    }
    Ok(())
}

/// Pull a pending op id out of a staging response like
/// "staged write (pending id 0): ..." or "staged undo (pending id 3) for ...".
fn parse_pending_id(text: &str) -> Option<u64> {
    let low = text.to_lowercase();
    let marker = "pending id ";
    let idx = low.find(marker)?;
    let rest = &low[idx + marker.len()..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let stage = std::env::args().nth(1).unwrap_or_else(|| "ping".into());
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run(&stage))
}

async fn run(stage: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url: std::sync::Arc<str> = MCP_URL.into();
    let transport: StreamableHttpClientTransport<reqwest::Client> =
        StreamableHttpClientTransport::from_uri(url);
    let client = Client.serve(transport).await?;

    match stage {
        "ping" => {
            let r = client
                .call_tool(CallToolRequestParams::new("ping").with_arguments(serde_json::Map::new()))
                .await?;
            println!("[MCP] {}", extract_text(&r));
            match dll_rpc(&trainlab_core::protocol::Request::Ping) {
                Ok(trainlab_core::protocol::Response::Pong { version }) => {
                    println!("[DLL] alive, inject v{version}");
                }
                other => println!("[DLL] unexpected: {other:?}"),
            }
        }
        "games" => {
            // games — list candidate game processes for attach_game.
            let r = client
                .call_tool(CallToolRequestParams::new("find_games").with_arguments(serde_json::Map::new()))
                .await?;
            println!("{}", extract_text(&r));
        }
        "attach" => {
            // attach <game> [inject] — attach to a game (find + inject + connect).
            let game = std::env::args().nth(2).expect("game exe name arg");
            let no_inject = std::env::args().nth(3).map(|s| s == "false").unwrap_or(false);
            let r = client
                .call_tool(CallToolRequestParams::new("attach_game").with_arguments(args(&[
                    ("game", serde_json::json!(game)),
                    ("inject", serde_json::json!(!no_inject)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "status" => {
            let r = client
                .call_tool(CallToolRequestParams::new("connection_status").with_arguments(serde_json::Map::new()))
                .await?;
            println!("{}", extract_text(&r));
        }
        "addcheat" => {
            // addcheat <label> value <addr> <type> [note]  — add a value cheat.
            // addcheat <label> toggle <target> [hook] [payload] [note]
            let label = std::env::args().nth(2).expect("label arg");
            let kind = std::env::args().nth(3).expect("kind arg (value|toggle)");
            let mut m = serde_json::Map::new();
            m.insert("label".into(), serde_json::json!(label));
            m.insert("kind".into(), serde_json::json!(kind));
            if kind == "value" {
                let addr = std::env::args().nth(4).expect("address arg");
                let vt = std::env::args().nth(5).expect("value_type arg");
                m.insert("address".into(), serde_json::json!(addr));
                m.insert("value_type".into(), serde_json::json!(vt));
                if let Some(n) = std::env::args().nth(6) {
                    m.insert("note".into(), serde_json::json!(n));
                }
            } else {
                let target = std::env::args().nth(4).expect("target arg");
                m.insert("target".into(), serde_json::json!(target));
                if let Some(h) = std::env::args().nth(5) {
                    m.insert("hook".into(), serde_json::json!(h));
                }
                if let Some(p) = std::env::args().nth(6) {
                    m.insert("payload".into(), serde_json::json!(p));
                }
            }
            let r = client
                .call_tool(CallToolRequestParams::new("add_cheat").with_arguments(m))
                .await?;
            println!("{}", extract_text(&r));
        }
        "cheats" => {
            let r = client
                .call_tool(CallToolRequestParams::new("list_cheats").with_arguments(serde_json::Map::new()))
                .await?;
            println!("{}", extract_text(&r));
        }
        "setcheat" => {
            // setcheat <id> <value> — stage a value write for a cheat.
            let id: u64 = std::env::args().nth(2).expect("cheat id").parse().expect("numeric");
            let value = std::env::args().nth(3).expect("value arg");
            let r = client
                .call_tool(CallToolRequestParams::new("set_cheat_value").with_arguments(args(&[
                    ("id", serde_json::json!(id)),
                    ("value", serde_json::json!(value)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "profiles" => {
            let r = client
                .call_tool(CallToolRequestParams::new("list_profiles").with_arguments(serde_json::Map::new()))
                .await?;
            println!("{}", extract_text(&r));
        }
        "loadprofile" => {
            // loadprofile <name> [run_setup]
            let name = std::env::args().nth(2).expect("profile name arg");
            let run_setup = std::env::args().nth(3).map(|s| s != "false").unwrap_or(true);
            let r = client
                .call_tool(CallToolRequestParams::new("load_profile").with_arguments(args(&[
                    ("profile", serde_json::json!(name)),
                    ("run_setup", serde_json::json!(run_setup)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "saveprofile" => {
            // saveprofile [file]
            let mut m = serde_json::Map::new();
            if let Some(f) = std::env::args().nth(2) {
                m.insert("file".into(), serde_json::json!(f));
            }
            let r = client
                .call_tool(CallToolRequestParams::new("save_profile").with_arguments(m))
                .await?;
            println!("{}", extract_text(&r));
        }
        "seed" => {
            // Seed value defaults to 0.0; pass a specific value to narrow to
            // resource-like floats (e.g. 300) instead of all zeroed memory.
            let val = std::env::args()
                .nth(2)
                .and_then(|s| s.parse::<f64>().ok())
                .unwrap_or(0.0);
            let r = client
                .call_tool(CallToolRequestParams::new("scan").with_arguments(args(&[
                    ("value_type", serde_json::json!("f32")),
                    ("value", serde_json::json!(val)),
                    ("alignment", serde_json::json!(4)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "seedi" => {
            // i32 seed: seedi <value> — scan for an i32 value (integer currency).
            let val = std::env::args().nth(2).and_then(|s| s.parse::<i64>().ok()).unwrap_or(0);
            let r = client
                .call_tool(CallToolRequestParams::new("scan").with_arguments(args(&[
                    ("value_type", serde_json::json!("i32")),
                    ("value", serde_json::json!(val)),
                    ("alignment", serde_json::json!(4)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "seedr" => {
            // Range seed: seedr <min> <max> — scan f32 in [min,max].
            let min = std::env::args().nth(2).and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0);
            let max = std::env::args().nth(3).and_then(|s| s.parse::<f64>().ok()).unwrap_or(min);
            let r = client
                .call_tool(CallToolRequestParams::new("scan").with_arguments(args(&[
                    ("value_type", serde_json::json!("f32")),
                    ("op", serde_json::json!("range")),
                    ("value", serde_json::json!(min)),
                    ("max", serde_json::json!(max)),
                    ("alignment", serde_json::json!(4)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "narrow" => {
            let r = client
                .call_tool(CallToolRequestParams::new("next").with_arguments(args(&[
                    ("op", serde_json::json!("changed")),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "write" => {
            // write <addr> <f32value> [confirm] — stages an f32 write (4 hex
            // bytes). Pass "confirm" as the 4th arg to also apply it, or call
            // the 'confirm' stage with the returned pending id.
            let addr = std::env::args().nth(2).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
            let val = std::env::args().nth(3).and_then(|s| s.parse::<f32>().ok()).unwrap_or(0.0);
            let do_confirm = std::env::args().nth(4).map(|s| s == "confirm").unwrap_or(false);
            let bytes = val.to_le_bytes();
            let hex = format!("{:02x}{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2], bytes[3]);
            stage_then_confirm(
                &client,
                "write",
                &[
                    ("address", serde_json::json!(format!("0x{:x}", addr))),
                    ("data", serde_json::json!(hex)),
                ],
                do_confirm,
            )
            .await?;
        }
        "writei" => {
            // writei <addr> <i32value> [confirm] — stages an i32 write (4 hex
            // bytes). Pass "confirm" as the 4th arg to also apply it.
            let addr = std::env::args().nth(2).and_then(|s| u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
            let val = std::env::args().nth(3).and_then(|s| s.parse::<i32>().ok()).unwrap_or(0);
            let do_confirm = std::env::args().nth(4).map(|s| s == "confirm").unwrap_or(false);
            let bytes = val.to_le_bytes();
            let hex = format!("{:02x}{:02x}{:02x}{:02x}", bytes[0], bytes[1], bytes[2], bytes[3]);
            stage_then_confirm(
                &client,
                "write",
                &[
                    ("address", serde_json::json!(format!("0x{:x}", addr))),
                    ("data", serde_json::json!(hex)),
                ],
                do_confirm,
            )
            .await?;
        }
        "read" => {
            // read an f32 at a raw address (direct DLL read, no MCP).
            let addr_str = std::env::args().nth(2).expect("address arg");
            let addr = parse_addr(&addr_str);
            match read_f32_dll(addr) {
                Some(v) => println!("f32 at {:#x} = {}", addr, v),
                None => println!("read failed"),
            }
        }
        "watch" => {
            let addr_str = std::env::args().nth(2).expect("address arg");
            let r = client
                .call_tool(CallToolRequestParams::new("watch_writes").with_arguments(args(&[
                    ("address", serde_json::json!(addr_str)),
                    ("len", serde_json::json!(4)),
                    ("one_shot", serde_json::json!(false)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "poll" => {
            let r = client
                .call_tool(CallToolRequestParams::new("watch_poll").with_arguments(serde_json::Map::new()))
                .await?;
            println!("{}", extract_text(&r));
        }
        "disasm" => {
            let addr_str = std::env::args().nth(2).expect("address arg");
            let r = client
                .call_tool(CallToolRequestParams::new("disassemble").with_arguments(args(&[
                    ("address", serde_json::json!(addr_str)),
                    ("len", serde_json::json!(48)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "dumpstruct" => {
            // dumpstruct <addr> <fieldspec...> — read a struct as typed fields.
            // Each field: name:type[:offset[:len]], e.g. "hp:f32", "name:cstr:8:64",
            // "flag:u8:4", "id:u32:0".
            let addr_str = std::env::args().nth(2).expect("address arg");
            let fields: Vec<String> = std::env::args().skip(3).collect();
            if fields.is_empty() {
                println!("usage: dumpstruct <addr> name:type[:offset[:len]] ...");
            } else {
                // Build the fields JSON array directly.
                let fields_json: Vec<serde_json::Value> = fields
                    .iter()
                    .filter_map(|spec| {
                        let parts: Vec<&str> = spec.split(':').collect();
                        if parts.len() < 2 {
                            return None;
                        }
                        let name = parts[0];
                        let value_type = parts[1];
                        let offset = parts.get(2).map(|s| s.parse::<u64>().unwrap_or(0)).unwrap_or(0);
                        let len = parts.get(3).map(|s| s.parse::<usize>().unwrap_or(0)).filter(|&l| l > 0);
                        let mut m = serde_json::Map::new();
                        m.insert("name".into(), serde_json::json!(name));
                        m.insert("value_type".into(), serde_json::json!(value_type));
                        m.insert("offset".into(), serde_json::json!(offset));
                        if let Some(l) = len {
                            m.insert("len".into(), serde_json::json!(l));
                        }
                        Some(serde_json::Value::Object(m))
                    })
                    .collect();
                if fields_json.is_empty() {
                    println!("no valid fields given; use name:type[:offset[:len]]");
                } else {
                    let r = client
                        .call_tool(CallToolRequestParams::new("dump_struct").with_arguments(args(&[
                            ("address", serde_json::json!(addr_str)),
                            ("fields", serde_json::json!(fields_json)),
                        ])))
                        .await?;
                    println!("{}", extract_text(&r));
                }
            }
        }
        "cave" => {
            let addr_str = std::env::args().nth(2).expect("target arg");
            // hook kind optional (default trampoline), payload optional, and an
            // optional 5th arg "confirm" to apply immediately.
            let hook = std::env::args().nth(3).unwrap_or_else(|| "trampoline".into());
            let payload = std::env::args().nth(4).unwrap_or_default();
            let do_confirm = std::env::args().nth(5).map(|s| s == "confirm").unwrap_or(false);
            stage_then_confirm(
                &client,
                "install_cave",
                &[
                    ("target", serde_json::json!(addr_str)),
                    ("hook", serde_json::json!(hook)),
                    ("payload", serde_json::json!(payload)),
                ],
                do_confirm,
            )
            .await?;
        }
        "clear" => {
            let r = client
                .call_tool(CallToolRequestParams::new("clear_breakpoints").with_arguments(args(&[])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "pending" => {
            let r = client
                .call_tool(CallToolRequestParams::new("list_pending").with_arguments(args(&[])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "confirm" => {
            // confirm <pending_id> — apply a staged mutation (human gate).
            let id: u64 = std::env::args()
                .nth(2)
                .expect("pending id arg")
                .parse()
                .expect("numeric id");
            let r = client
                .call_tool(CallToolRequestParams::new("confirm_op").with_arguments(args(&[
                    ("id", serde_json::json!(id)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "reject" => {
            // reject <pending_id> — discard a staged mutation.
            let id: u64 = std::env::args()
                .nth(2)
                .expect("pending id arg")
                .parse()
                .expect("numeric id");
            let r = client
                .call_tool(CallToolRequestParams::new("reject_op").with_arguments(args(&[
                    ("id", serde_json::json!(id)),
                ])))
                .await?;
            println!("{}", extract_text(&r));
        }
        "restore" => {
            let id: u64 = std::env::args()
                .nth(2)
                .expect("undo id arg")
                .parse()
                .expect("numeric id");
            // undo now stages; apply it via the same confirm path.
            stage_then_confirm(
                &client,
                "undo",
                &[("id", serde_json::json!(id))],
                true,
            )
            .await?;
        }
        other => println!("unknown stage: {other}"),
    }

    client.cancel().await?;
    Ok(())
}

fn args(map: &[(&str, serde_json::Value)]) -> serde_json::Map<String, serde_json::Value> {
    map.iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

fn parse_addr(s: &str) -> u64 {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).expect("hex addr")
    } else {
        s.parse().expect("decimal addr")
    }
}
