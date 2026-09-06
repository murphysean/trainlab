//! Steamworks P2P and networking traffic interception hooks (`steam_api64.dll` / `steam_api.dll`).
//!
//! Intercepts in-game Steam P2P traffic before transport framing and SDR payload encryption:
//! - `SteamAPI_ISteamNetworking_SendP2PPacket`
//! - `SteamAPI_ISteamNetworking_ReadP2PPacket`
//! - `SteamAPI_ISteamNetworkingMessages_SendMessageToUser`
//! - `SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel`
//!
//! This surfaces clean, unencrypted game payloads along with the remote peer's 64-bit Steam ID
//! and virtual networking channel.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;

use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};

use trainlab_core::protocol::{PacketDirection, PacketKind};

/// Flat C Steamworks function signatures.
/// bool SteamAPI_ISteamNetworking_SendP2PPacket(intptr_t instancePtr, uint64 steamIDRemote, const void *pubData, uint32 cubData, int eP2PSendType, int nChannel);
type FnSteamNetworkingSendP2PPacket = unsafe extern "system" fn(
    *mut c_void, // this / instance
    u64,         // steamIDRemote
    *const u8,   // pubData
    u32,         // cubData
    i32,         // eP2PSendType
    i32,         // nChannel
) -> bool;

/// bool SteamAPI_ISteamNetworking_ReadP2PPacket(intptr_t instancePtr, void *pubDest, uint32 cubDest, uint32 *pcubMsgSize, uint64 *psteamIDRemote, int nChannel);
type FnSteamNetworkingReadP2PPacket = unsafe extern "system" fn(
    *mut c_void, // this / instance
    *mut u8,     // pubDest
    u32,         // cubDest
    *mut u32,    // pcubMsgSize
    *mut u64,    // psteamIDRemote
    i32,         // nChannel
) -> bool;

/// SteamNetworkingIdentity struct layout in Steamworks (starts with type and 64-bit Steam ID).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SteamNetworkingIdentity {
    pub m_eType: i32,
    pub m_cbSize: i32,
    pub m_steamID64: u64,
    pub m_reserved: [u8; 120],
}

/// SteamNetworkingMessage_t pointer layout.
#[repr(C)]
pub struct SteamNetworkingMessage {
    pub m_pData: *mut u8,
    pub m_cbSize: u32,
    pub m_conn: u32,
    pub m_identityPeer: SteamNetworkingIdentity,
    pub m_nConnUserData: i64,
    pub m_usecTimeReceived: i64,
    pub m_nMessageNumber: i64,
    pub m_pfnFreeData: *mut c_void,
    pub m_pfnRelease: *mut c_void,
    pub m_nChannel: i32,
    pub m_nFlags: i32,
    pub m_nUserData: i64,
    pub m_idxLane: u16,
    pub m_pad: u16,
}

/// int64 SteamAPI_ISteamNetworkingMessages_SendMessageToUser(intptr_t instancePtr, const SteamNetworkingIdentity *identityRemote, const void *pubData, uint32 cubData, int nSendFlags, int nRemoteChannel);
type FnSteamNetworkingMessagesSendMessageToUser = unsafe extern "system" fn(
    *mut c_void,
    *const SteamNetworkingIdentity,
    *const u8,
    u32,
    i32,
    i32,
) -> i64;

/// int SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel(intptr_t instancePtr, int nLocalChannel, SteamNetworkingMessage_t **ppOutMessages, int nMaxMessages);
type FnSteamNetworkingMessagesReceiveMessagesOnChannel = unsafe extern "system" fn(
    *mut c_void,
    i32,
    *mut *mut SteamNetworkingMessage,
    i32,
) -> i32;

/// int SteamAPI_ISteamNetworkingSockets_SendMessageToConnection(intptr_t instancePtr, uint32 hConn, const void *pubData, uint32 cubData, int nSendFlags, int64 *pOutMessageNumber);
type FnSteamNetworkingSocketsSendMessageToConnection = unsafe extern "system" fn(
    *mut c_void,
    u32,
    *const u8,
    u32,
    i32,
    *mut i64,
) -> i32;

/// int SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection(intptr_t instancePtr, uint32 hConn, SteamNetworkingMessage_t **ppOutMessages, int nMaxMessages);
type FnSteamNetworkingSocketsReceiveMessagesOnConnection = unsafe extern "system" fn(
    *mut c_void,
    u32,
    *mut *mut SteamNetworkingMessage,
    i32,
) -> i32;

static ORIGINAL_SEND_P2P: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_READ_P2P: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SEND_MESSAGE_TO_USER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECEIVE_MESSAGES: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SOCKETS_SEND_MESSAGE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SOCKETS_RECEIVE_MESSAGES: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

static STEAMWORKS_HOOKED: AtomicBool = AtomicBool::new(false);

/// Hooked `SteamAPI_ISteamNetworking_SendP2PPacket` (Legacy P2P outbound).
pub unsafe extern "system" fn hooked_steam_networking_send_p2p_packet(
    instance: *mut c_void,
    steam_id_remote: u64,
    pub_data: *const u8,
    cub_data: u32,
    p2p_send_type: i32,
    n_channel: i32,
) -> bool {
    let orig = ORIGINAL_SEND_P2P.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSteamNetworkingSendP2PPacket = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(instance, steam_id_remote, pub_data, cub_data, p2p_send_type, n_channel) }
    } else {
        false
    };

    if ret && !pub_data.is_null() && cub_data > 0 {
        super::count_raw_packet(PacketKind::Steam, PacketDirection::Outbound, cub_data as usize);
        let slice = unsafe { std::slice::from_raw_parts(pub_data, cub_data as usize) };
        let remote_ep = format!("steam:{}", steam_id_remote);
        let url = format!("P2P Send (ch:{}, type:{})", n_channel, p2p_send_type);

        super::record_packet(
            PacketKind::Steam,
            PacketDirection::Outbound,
            Some("steam:local".into()),
            Some(remote_ep),
            Some(url),
            None,
            slice,
        );
    }

    ret
}

/// Hooked `SteamAPI_ISteamNetworking_ReadP2PPacket` (Legacy P2P inbound).
pub unsafe extern "system" fn hooked_steam_networking_read_p2p_packet(
    instance: *mut c_void,
    pub_dest: *mut u8,
    cub_dest: u32,
    pcub_msg_size: *mut u32,
    psteam_id_remote: *mut u64,
    n_channel: i32,
) -> bool {
    let orig = ORIGINAL_READ_P2P.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSteamNetworkingReadP2PPacket = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(instance, pub_dest, cub_dest, pcub_msg_size, psteam_id_remote, n_channel) }
    } else {
        false
    };

    if ret && !pub_dest.is_null() && !pcub_msg_size.is_null() {
        let msg_size = unsafe { *pcub_msg_size } as usize;
        let data_len = msg_size.min(cub_dest as usize);
        if data_len > 0 {
            super::count_raw_packet(PacketKind::Steam, PacketDirection::Inbound, data_len);
            let slice = unsafe { std::slice::from_raw_parts(pub_dest, data_len) };
            let steam_id = if !psteam_id_remote.is_null() {
                unsafe { *psteam_id_remote }
            } else {
                0
            };
            let remote_ep = format!("steam:{}", steam_id);
            let url = format!("P2P Recv (ch:{})", n_channel);

            super::record_packet(
                PacketKind::Steam,
                PacketDirection::Inbound,
                Some(remote_ep),
                Some("steam:local".into()),
                Some(url),
                None,
                slice,
            );
        }
    }

    ret
}

/// Hooked `SteamAPI_ISteamNetworkingMessages_SendMessageToUser` (Modern SteamNetworkingMessages outbound).
pub unsafe extern "system" fn hooked_steam_networking_messages_send_message_to_user(
    instance: *mut c_void,
    identity_remote: *const SteamNetworkingIdentity,
    pub_data: *const u8,
    cub_data: u32,
    n_send_flags: i32,
    n_remote_channel: i32,
) -> i64 {
    let orig = ORIGINAL_SEND_MESSAGE_TO_USER.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSteamNetworkingMessagesSendMessageToUser = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(instance, identity_remote, pub_data, cub_data, n_send_flags, n_remote_channel) }
    } else {
        0
    };

    if ret > 0 && !pub_data.is_null() && cub_data > 0 {
        super::count_raw_packet(PacketKind::Steam, PacketDirection::Outbound, cub_data as usize);
        let slice = unsafe { std::slice::from_raw_parts(pub_data, cub_data as usize) };
        let steam_id = if !identity_remote.is_null() {
            unsafe { (*identity_remote).m_steamID64 }
        } else {
            0
        };
        let remote_ep = format!("steam:{}", steam_id);
        let url = format!("SteamMessages Send (ch:{}, flags:{:#x})", n_remote_channel, n_send_flags);

        super::record_packet(
            PacketKind::Steam,
            PacketDirection::Outbound,
            Some("steam:local".into()),
            Some(remote_ep),
            Some(url),
            None,
            slice,
        );
    }

    ret
}

/// Hooked `SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel` (Modern SteamNetworkingMessages inbound).
pub unsafe extern "system" fn hooked_steam_networking_messages_receive_messages_on_channel(
    instance: *mut c_void,
    n_local_channel: i32,
    pp_out_messages: *mut *mut SteamNetworkingMessage,
    n_max_messages: i32,
) -> i32 {
    let orig = ORIGINAL_RECEIVE_MESSAGES.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSteamNetworkingMessagesReceiveMessagesOnChannel = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(instance, n_local_channel, pp_out_messages, n_max_messages) }
    } else {
        0
    };

    if ret > 0 && !pp_out_messages.is_null() {
        let count = (ret as usize).min(n_max_messages as usize);
        let msgs = unsafe { std::slice::from_raw_parts(pp_out_messages, count) };
        for &msg_ptr in msgs {
            if !msg_ptr.is_null() {
                let msg = unsafe { &*msg_ptr };
                if !msg.m_pData.is_null() && msg.m_cbSize > 0 {
                    super::count_raw_packet(PacketKind::Steam, PacketDirection::Inbound, msg.m_cbSize as usize);
                    let slice = unsafe { std::slice::from_raw_parts(msg.m_pData, msg.m_cbSize as usize) };
                    let steam_id = msg.m_identityPeer.m_steamID64;
                    let remote_ep = format!("steam:{}", steam_id);
                    let url = format!("SteamMessages Recv (ch:{}, lane:{})", msg.m_nChannel, msg.m_idxLane);

                    super::record_packet(
                        PacketKind::Steam,
                        PacketDirection::Inbound,
                        Some(remote_ep),
                        Some("steam:local".into()),
                        Some(url),
                        None,
                        slice,
                    );
                }
            }
        }
    }

    ret
}

/// Hooked `SteamAPI_ISteamNetworkingSockets_SendMessageToConnection` (SteamNetworkingSockets connection outbound).
pub unsafe extern "system" fn hooked_steam_networking_sockets_send_message_to_connection(
    instance: *mut c_void,
    h_conn: u32,
    pub_data: *const u8,
    cub_data: u32,
    n_send_flags: i32,
    p_out_message_number: *mut i64,
) -> i32 {
    let orig = ORIGINAL_SOCKETS_SEND_MESSAGE.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSteamNetworkingSocketsSendMessageToConnection = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(instance, h_conn, pub_data, cub_data, n_send_flags, p_out_message_number) }
    } else {
        0
    };

    // k_EResultOK is 1 in Steamworks
    if (ret == 1 || ret > 0) && !pub_data.is_null() && cub_data > 0 {
        super::count_raw_packet(PacketKind::Steam, PacketDirection::Outbound, cub_data as usize);
        let slice = unsafe { std::slice::from_raw_parts(pub_data, cub_data as usize) };
        let remote_ep = format!("steam:conn:{}", h_conn);
        let url = format!("SteamSockets Send (conn:{}, flags:{:#x})", h_conn, n_send_flags);

        super::record_packet(
            PacketKind::Steam,
            PacketDirection::Outbound,
            Some("steam:local".into()),
            Some(remote_ep),
            Some(url),
            None,
            slice,
        );
    }

    ret
}

/// Hooked `SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection` (SteamNetworkingSockets connection inbound).
pub unsafe extern "system" fn hooked_steam_networking_sockets_receive_messages_on_connection(
    instance: *mut c_void,
    h_conn: u32,
    pp_out_messages: *mut *mut SteamNetworkingMessage,
    n_max_messages: i32,
) -> i32 {
    let orig = ORIGINAL_SOCKETS_RECEIVE_MESSAGES.load(Ordering::Relaxed);
    let ret = if !orig.is_null() {
        let orig_fn: FnSteamNetworkingSocketsReceiveMessagesOnConnection = unsafe { std::mem::transmute(orig) };
        unsafe { orig_fn(instance, h_conn, pp_out_messages, n_max_messages) }
    } else {
        0
    };

    if ret > 0 && !pp_out_messages.is_null() {
        let count = (ret as usize).min(n_max_messages as usize);
        let msgs = unsafe { std::slice::from_raw_parts(pp_out_messages, count) };
        for &msg_ptr in msgs {
            if !msg_ptr.is_null() {
                let msg = unsafe { &*msg_ptr };
                if !msg.m_pData.is_null() && msg.m_cbSize > 0 {
                    super::count_raw_packet(PacketKind::Steam, PacketDirection::Inbound, msg.m_cbSize as usize);
                    let slice = unsafe { std::slice::from_raw_parts(msg.m_pData, msg.m_cbSize as usize) };
                    let steam_id = msg.m_identityPeer.m_steamID64;
                    let remote_ep = if steam_id != 0 {
                        format!("steam:{}", steam_id)
                    } else {
                        format!("steam:conn:{}", h_conn)
                    };
                    let url = format!("SteamSockets Recv (conn:{}, ch:{}, lane:{})", h_conn, msg.m_nChannel, msg.m_idxLane);

                    super::record_packet(
                        PacketKind::Steam,
                        PacketDirection::Inbound,
                        Some(remote_ep),
                        Some("steam:local".into()),
                        Some(url),
                        None,
                        slice,
                    );
                }
            }
        }
    }

    ret
}

/// Install detour hook at an absolute function address.
unsafe fn install_hook_at(
    target_u64: u64,
    hook_name: &str,
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> (bool, String) {
    let payload = trainlab_cave::emitter::jmp_abs(callback_addr);
    let hook = trainlab_cave::cave::HookKind::Trampoline {
        payload: payload.clone(),
        jump: trainlab_cave::cave::JumpStyle::Absolute,
    };

    let mem = trainlab_core::memory::SelfProcess;
    let read = |addr: u64, len: usize| -> Result<Vec<u8>, String> {
        use trainlab_core::memory::ProcessMemory;
        mem.read(addr, len).map_err(|e| e.to_string())
    };
    let write = |addr: u64, data: &[u8]| -> Result<usize, String> {
        use trainlab_core::memory::ProcessMemory;
        mem.write(addr, data).map_err(|e| e.to_string())
    };
    let allocate = |size: usize, exec: bool| -> Result<u64, String> {
        crate::allocate(size, exec)
    };

    match trainlab_cave::cave::install(target_u64, hook, read, write, allocate) {
        Ok(installed) => {
            target_orig.store(
                (installed.cave_addr + payload.len() as u64) as *mut c_void,
                Ordering::SeqCst,
            );
            tracing::info!(
                "Hooked Steamworks {} at 0x{:X} -> trampoline at 0x{:X}",
                hook_name,
                target_u64,
                installed.cave_addr
            );
            (true, format!("{}=Y", hook_name))
        }
        Err(e) => {
            tracing::warn!(
                "Failed to hook Steamworks {}: {}",
                hook_name,
                e
            );
            (false, format!("{}=FAIL({})", hook_name, e))
        }
    }
}

/// Install detour hook for a specific Steamworks export.
unsafe fn install_hook(
    module_handle: *mut c_void,
    proc_name: &[u8],
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> (bool, String) {
    let proc_name_str = String::from_utf8_lossy(proc_name).trim_end_matches('\0').to_string();
    let fn_ptr = unsafe { GetProcAddress(module_handle, proc_name.as_ptr()) };
    if let Some(target_fn) = fn_ptr {
        unsafe {
            install_hook_at(
                target_fn as u64,
                &proc_name_str,
                callback_addr,
                target_orig,
            )
        }
    } else {
        (false, format!("{}=FAIL(GetProcAddress failed)", proc_name_str))
    }
}

/// Scan a PE module in memory for a function referencing a string pattern.
unsafe fn find_func_referencing_str(module_base: u64, target_str: &[u8]) -> Option<u64> {
    use trainlab_core::memory::ProcessMemory;
    let mem = trainlab_core::memory::SelfProcess;

    // Read DOS header -> e_lfanew
    let dos_hdr = mem.read(module_base, 0x40).ok()?;
    if dos_hdr.len() < 0x40 || dos_hdr[0..2] != [0x4D, 0x5A] {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(dos_hdr[0x3c..0x40].try_into().ok()?) as u64;

    // Read NT header
    let nt_hdr = mem.read(module_base + e_lfanew, 0x18).ok()?;
    if nt_hdr.len() < 0x18 || nt_hdr[0..4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }
    let num_sections = u16::from_le_bytes(nt_hdr[6..8].try_into().ok()?) as usize;
    let opt_hdr_size = u16::from_le_bytes(nt_hdr[20..22].try_into().ok()?) as u64;

    let sec_table_base = module_base + e_lfanew + 24 + opt_hdr_size;
    let mut text_rva = 0u64;
    let mut text_size = 0usize;
    let mut rdata_rva = 0u64;
    let mut rdata_size = 0usize;

    for i in 0..num_sections {
        let sec_hdr = mem.read(sec_table_base + (i * 40) as u64, 40).ok()?;
        let sec_name = &sec_hdr[0..8];
        let va = u32::from_le_bytes(sec_hdr[12..16].try_into().ok()?) as u64;
        let vsize = u32::from_le_bytes(sec_hdr[8..12].try_into().ok()?) as usize;

        if sec_name.starts_with(b".text") {
            text_rva = va;
            text_size = vsize;
        } else if sec_name.starts_with(b".rdata") || sec_name.starts_with(b".rodata") {
            rdata_rva = va;
            rdata_size = vsize;
        }
    }

    if text_size == 0 || rdata_size == 0 {
        return None;
    }

    let rdata_bytes = mem.read(module_base + rdata_rva, rdata_size).ok()?;
    // Find string within rdata
    let str_offset_in_rdata = rdata_bytes.windows(target_str.len()).position(|w| w == target_str)?;
    let target_str_va = module_base + rdata_rva + str_offset_in_rdata as u64;

    let text_bytes = mem.read(module_base + text_rva, text_size).ok()?;

    // Search for instructions referencing target_str_va via RIP displacement:
    // lea r8, [rip + disp32] (4c 8d 05 xx xx xx xx)
    // or lea rdx, [rip + disp32] (48 8d 15 xx xx xx xx)
    for i in 0..text_bytes.len().saturating_sub(7) {
        if (text_bytes[i] == 0x4C && text_bytes[i + 1] == 0x8D && text_bytes[i + 2] == 0x05)
            || (text_bytes[i] == 0x48 && text_bytes[i + 1] == 0x8D && text_bytes[i + 2] == 0x15)
        {
            let disp = i32::from_le_bytes(text_bytes[i + 3..i + 7].try_into().ok()?) as i64;
            let next_rip = (module_base + text_rva + (i as u64) + 7) as i64;
            if (next_rip + disp) as u64 == target_str_va {
                // Scan backwards for function prologue (push rbp: 0x55 followed by 0x48, 0x41, 0x53, or 0x89)
                let start_idx = i.saturating_sub(256);
                let mut p = i;
                while p > start_idx {
                    if text_bytes[p] == 0x55
                        && (text_bytes[p + 1] == 0x48
                            || text_bytes[p + 1] == 0x41
                            || text_bytes[p + 1] == 0x53
                            || text_bytes[p + 1] == 0x89)
                    {
                        return Some(module_base + text_rva + p as u64);
                    }
                    p -= 1;
                }
            }
        }
    }

    None
}

/// Initialize Steamworks P2P networking hooks.
pub fn init_steamworks_hooks() {
    std::thread::sleep(Duration::from_millis(1000));

    unsafe {
        let mut hooked_any = false;

        // 1. Probe steam_api64.dll / steam_api.dll (Standard Steamworks API)
        let mut steam_mod = GetModuleHandleA(b"steam_api64.dll\0".as_ptr());
        if steam_mod.is_null() {
            steam_mod = GetModuleHandleA(b"steam_api.dll\0".as_ptr());
        }

        let mut results = Vec::new();

        if !steam_mod.is_null() {
            // Legacy SteamNetworking
            let (h_p2p_send, r_p2p_send) = install_hook(
                steam_mod,
                b"SteamAPI_ISteamNetworking_SendP2PPacket\0",
                hooked_steam_networking_send_p2p_packet as *const () as u64,
                &ORIGINAL_SEND_P2P,
            );
            results.push(r_p2p_send);
            hooked_any |= h_p2p_send;

            let (h_p2p_read, r_p2p_read) = install_hook(
                steam_mod,
                b"SteamAPI_ISteamNetworking_ReadP2PPacket\0",
                hooked_steam_networking_read_p2p_packet as *const () as u64,
                &ORIGINAL_READ_P2P,
            );
            results.push(r_p2p_read);
            hooked_any |= h_p2p_read;

            // Modern SteamNetworkingMessages
            let (h_msg_send, r_msg_send) = install_hook(
                steam_mod,
                b"SteamAPI_ISteamNetworkingMessages_SendMessageToUser\0",
                hooked_steam_networking_messages_send_message_to_user as *const () as u64,
                &ORIGINAL_SEND_MESSAGE_TO_USER,
            );
            results.push(r_msg_send);
            hooked_any |= h_msg_send;

            let (h_msg_recv, r_msg_recv) = install_hook(
                steam_mod,
                b"SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel\0",
                hooked_steam_networking_messages_receive_messages_on_channel as *const () as u64,
                &ORIGINAL_RECEIVE_MESSAGES,
            );
            results.push(r_msg_recv);
            hooked_any |= h_msg_recv;

            // Modern SteamNetworkingSockets flat C exports (if present in steam_api64)
            let (h_sock_send, r_sock_send) = install_hook(
                steam_mod,
                b"SteamAPI_ISteamNetworkingSockets_SendMessageToConnection\0",
                hooked_steam_networking_sockets_send_message_to_connection as *const () as u64,
                &ORIGINAL_SOCKETS_SEND_MESSAGE,
            );
            results.push(r_sock_send);
            hooked_any |= h_sock_send;

            let (h_sock_recv, r_sock_recv) = install_hook(
                steam_mod,
                b"SteamAPI_ISteamNetworkingSockets_ReceiveMessagesOnConnection\0",
                hooked_steam_networking_sockets_receive_messages_on_connection as *const () as u64,
                &ORIGINAL_SOCKETS_RECEIVE_MESSAGES,
            );
            results.push(r_sock_recv);
            hooked_any |= h_sock_recv;
        } else {
            results.push("steam_api64.dll=FAIL(not loaded)".to_string());
        }

        // 2. Probe lsteamclient.dll / lsteamclient64.dll (Wine / Proton Steam Bridge)
        // This is where games like Helldivers dispatch ISteamNetworkingSockets under Proton.
        let mut lsteam_mod = GetModuleHandleA(b"lsteamclient.dll\0".as_ptr());
        if lsteam_mod.is_null() {
            lsteam_mod = GetModuleHandleA(b"lsteamclient64.dll\0".as_ptr());
        }

        if !lsteam_mod.is_null() {
            let base = lsteam_mod as u64;
            tracing::info!("Found lsteamclient.dll loaded at 0x{:X}; scanning for SteamNetworkingSockets", base);

            // 2a. Probe Legacy ISteamNetworking versions (006 down to 001)
            // Games like Helldivers use legacy SteamNetworking005 for all P2P datagrams.
            let legacy_versions = ["006", "005", "004", "003", "002", "001"];
            let mut hooked_lsteam_p2p_send = false;
            let mut hooked_lsteam_p2p_read = false;

            for v in legacy_versions {
                if !hooked_lsteam_p2p_send {
                    let send_str = format!("winISteamNetworking_SteamNetworking{}_SendP2PPacket\0", v);
                    if let Some(send_fn) = find_func_referencing_str(base, send_str.as_bytes()) {
                        let (h, r) = install_hook_at(
                            send_fn,
                            &format!("lsteamclient:SendP2PPacket({})", v),
                            hooked_steam_networking_send_p2p_packet as *const () as u64,
                            &ORIGINAL_SEND_P2P,
                        );
                        if h {
                            hooked_lsteam_p2p_send = true;
                            hooked_any = true;
                        }
                        results.push(r);
                    }
                }

                if !hooked_lsteam_p2p_read {
                    let read_str = format!("winISteamNetworking_SteamNetworking{}_ReadP2PPacket\0", v);
                    if let Some(read_fn) = find_func_referencing_str(base, read_str.as_bytes()) {
                        let (h, r) = install_hook_at(
                            read_fn,
                            &format!("lsteamclient:ReadP2PPacket({})", v),
                            hooked_steam_networking_read_p2p_packet as *const () as u64,
                            &ORIGINAL_READ_P2P,
                        );
                        if h {
                            hooked_lsteam_p2p_read = true;
                            hooked_any = true;
                        }
                        results.push(r);
                    }
                }

                if hooked_lsteam_p2p_send && hooked_lsteam_p2p_read {
                    break;
                }
            }

            if !hooked_lsteam_p2p_send {
                results.push("lsteamclient:SendP2PPacket=FAIL(pattern not found)".into());
            }
            if !hooked_lsteam_p2p_read {
                results.push("lsteamclient:ReadP2PPacket=FAIL(pattern not found)".into());
            }

            // 2b. Probe Modern ISteamNetworkingSockets versions in descending priority (013 down to 002)
            let socket_versions = ["013", "012", "009", "008", "006", "004", "002"];
            let mut hooked_lsteam_sockets_send = false;
            let mut hooked_lsteam_sockets_recv = false;

            for v in socket_versions {
                if !hooked_lsteam_sockets_send {
                    let send_str = format!("ISteamNetworkingSockets_SteamNetworkingSockets{}_SendMessageToConnection\0", v);
                    if let Some(send_fn) = find_func_referencing_str(base, send_str.as_bytes()) {
                        let (h, r) = install_hook_at(
                            send_fn,
                            &format!("lsteamclient:SendMessageToConnection({})", v),
                            hooked_steam_networking_sockets_send_message_to_connection as *const () as u64,
                            &ORIGINAL_SOCKETS_SEND_MESSAGE,
                        );
                        if h {
                            hooked_lsteam_sockets_send = true;
                            hooked_any = true;
                        }
                        results.push(r);
                    }
                }

                if !hooked_lsteam_sockets_recv {
                    let recv_str = format!("ISteamNetworkingSockets_SteamNetworkingSockets{}_ReceiveMessagesOnConnection\0", v);
                    if let Some(recv_fn) = find_func_referencing_str(base, recv_str.as_bytes()) {
                        let (h, r) = install_hook_at(
                            recv_fn,
                            &format!("lsteamclient:ReceiveMessagesOnConnection({})", v),
                            hooked_steam_networking_sockets_receive_messages_on_connection as *const () as u64,
                            &ORIGINAL_SOCKETS_RECEIVE_MESSAGES,
                        );
                        if h {
                            hooked_lsteam_sockets_recv = true;
                            hooked_any = true;
                        }
                        results.push(r);
                    }
                }

                if hooked_lsteam_sockets_send && hooked_lsteam_sockets_recv {
                    break;
                }
            }

            if !hooked_lsteam_sockets_send {
                results.push("lsteamclient:SendMessageToConnection=FAIL(pattern not found)".into());
            }
            if !hooked_lsteam_sockets_recv {
                results.push("lsteamclient:ReceiveMessagesOnConnection=FAIL(pattern not found)".into());
            }
        } else {
            results.push("lsteamclient.dll=FAIL(not loaded)".into());
        }

        if hooked_any {
            STEAMWORKS_HOOKED.store(true, Ordering::SeqCst);
            tracing::info!(
                "[NETWORK] Steamworks / SteamNetworkingSockets hooks installed: [{}]",
                results.join(", ")
            );
        } else {
            tracing::warn!(
                "[NETWORK] Failed to install any Steamworks hooks: [{}]",
                results.join(", ")
            );
        }

        if let Ok(mut out) = crate::render::overlay::OUTBOUND_EVENTS.lock() {
            out.push(trainlab_core::protocol::Event::NetworkHooksInstalled {
                subsystem: "steamworks".to_string(),
                results,
            });
        }
    }
}

