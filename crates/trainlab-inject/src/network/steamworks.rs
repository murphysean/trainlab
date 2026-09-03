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

static ORIGINAL_SEND_P2P: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_READ_P2P: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_SEND_MESSAGE_TO_USER: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static ORIGINAL_RECEIVE_MESSAGES: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

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

/// Install detour hook for a specific Steamworks export.
unsafe fn install_hook(
    module_handle: *mut c_void,
    proc_name: &[u8],
    callback_addr: u64,
    target_orig: &AtomicPtr<c_void>,
) -> bool {
    let fn_ptr = unsafe { GetProcAddress(module_handle, proc_name.as_ptr()) };
    if let Some(target_fn) = fn_ptr {
        let target_u64 = target_fn as u64;
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
                    String::from_utf8_lossy(proc_name),
                    target_u64,
                    installed.cave_addr
                );
                true
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to hook Steamworks {}: {}",
                    String::from_utf8_lossy(proc_name),
                    e
                );
                false
            }
        }
    } else {
        false
    }
}

/// Initialize Steamworks P2P networking hooks.
pub fn init_steamworks_hooks() {
    std::thread::sleep(Duration::from_millis(1000));

    unsafe {
        // Find steam_api64.dll or steam_api.dll if loaded in game process
        let mut steam_mod = GetModuleHandleA(b"steam_api64.dll\0".as_ptr());
        if steam_mod.is_null() {
            steam_mod = GetModuleHandleA(b"steam_api.dll\0".as_ptr());
        }
        if steam_mod.is_null() {
            tracing::info!("steam_api(64).dll not loaded in process; skipping Steamworks P2P hooks");
            return;
        }

        let mut hooked_any = false;

        // Legacy SteamNetworking
        hooked_any |= install_hook(
            steam_mod,
            b"SteamAPI_ISteamNetworking_SendP2PPacket\0",
            hooked_steam_networking_send_p2p_packet as *const () as u64,
            &ORIGINAL_SEND_P2P,
        );
        hooked_any |= install_hook(
            steam_mod,
            b"SteamAPI_ISteamNetworking_ReadP2PPacket\0",
            hooked_steam_networking_read_p2p_packet as *const () as u64,
            &ORIGINAL_READ_P2P,
        );

        // Modern SteamNetworkingMessages
        hooked_any |= install_hook(
            steam_mod,
            b"SteamAPI_ISteamNetworkingMessages_SendMessageToUser\0",
            hooked_steam_networking_messages_send_message_to_user as *const () as u64,
            &ORIGINAL_SEND_MESSAGE_TO_USER,
        );
        hooked_any |= install_hook(
            steam_mod,
            b"SteamAPI_ISteamNetworkingMessages_ReceiveMessagesOnChannel\0",
            hooked_steam_networking_messages_receive_messages_on_channel as *const () as u64,
            &ORIGINAL_RECEIVE_MESSAGES,
        );

        if hooked_any {
            STEAMWORKS_HOOKED.store(true, Ordering::SeqCst);
            tracing::info!("Steamworks P2P traffic interception hooks installed successfully");
        }
    }
}
