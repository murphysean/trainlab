Yes, hooking at the raw socket level (send/recv) only captures bytes after encryption has already happened on the wire. Because our DLL is already loaded
  directly inside the game's address space, we can intercept the buffers before they are passed into the crypto pipeline (on egress) or after they have
  been decrypted (on ingress).
  Here is how that works depending on the transport layer:
  ──────
  ### 1. Windows TLS / HTTPS: Schannel (secur32.dll / sspicli.dll)

  Most Windows applications using native TLS rely on Windows SChannel (Security Support Provider Interface).

  • Where to hook:
      • Outbound (pre-encryption): EncryptMessage in secur32.dll
        SECURITY_STATUS EncryptMessage(
          PCtxtHandle    phContext,
          ULONG          fQOP,
          PSecBufferDesc pMessage,
          ULONG          MessageSeqNo
        );
      pMessage contains an array of SecBuffer structs. One of those buffers has type SECBUFFER_DATA containing the raw, unencrypted application payload
      (HTTP requests, JSON, protobufs). Hooking this detour lets us read the plain-text body before SChannel wraps it into TLS records.
      • Inbound (post-decryption): DecryptMessage in secur32.dll
        SECURITY_STATUS DecryptMessage(
          PCtxtHandle    phContext,
          PSecBufferDesc pMessage,
          ULONG          MessageSeqNo,
          PULONG         pfQOP
        );
      Calling the original DecryptMessage first, then inspecting pMessage->pBuffers where BufferType == SECBUFFER_DATA, yields the plaintext response
      payload returned from the server.

  ──────

  If the game statically links or ships its own crypto dynamic library (e.g. libssl.dll, libcrypto.dll):
  ### 2. User-Mode TLS Libraries: OpenSSL / BoringSSL / mbedTLS

  • Where to hook:
      • SSL_write(SSL *ssl, const void *buf, int num): buf is the plaintext buffer passed right before encryption.
      • SSL_read(SSL *ssl, void *buf, int num): Inspect buf after the original function returns >0.

  ──────
  ### 3. Steam P2P / Multiplayer Sync: steam_api64.dll & Steam Networking Sockets
  For game multiplayer synchronization (like Steam P2P or Valve's Steam Datagram Relay), games typically bypass raw Winsock and call into steam_api64.dll
  or steamnetworkingsockets.dll.
  • Where to hook:
      • SteamNetworkingMessages / ISteamNetworkingSockets:
          • ISteamNetworkingSockets::SendMessageToConnection(HSteamNetConnection conn, const void *pData, uint32 cbData, int nSendFlags, int64
          *pOutMessageNumber)
          • ISteamNetworkingSockets::ReceiveMessagesOnConnection(HSteamNetConnection conn, SteamNetworkingMessage_t **ppOutMessages, int nMaxMessages)
          • ISteamNetworkingMessages::SendMessageToUser(...)
          • ISteamNetworkingMessages::ReceiveMessagesOnChannel(...)
      • The SteamNetworkingMessage_t struct holds:
          • m_pData (pointer to the raw message payload)
          • m_cbSize (payload size)
          • m_identityPeer (SteamID / networking identity of the peer)
          • m_nChannel (logical virtual channel ID)
  Hooking these interfaces exposes the game's actual multiplayer entity state, RPCs, and player movement sync packets in plaintext with clear peer
  identifiers.
  ──────
  ### Next Steps
  1. SChannel Detours: We can add detour hooks for EncryptMessage and DecryptMessage in secur32.dll to capture unencrypted backend HTTPS REST traffic
  alongside our WinHTTP hooks.
  2. SteamNetworking Interface Hook: We can export/intercept the ISteamNetworkingSockets and ISteamNetworkingMessages vtables to capture gameplay
  multiplayer sync traffic.
