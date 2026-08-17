fn main() {
    // Embed the Windows application manifest so trainlab-gui.exe requests
    // elevation (requireAdministrator). This lets the trainer OpenProcess
    // games that themselves run elevated (e.g. Helldivers runs as admin);
    // without it, a non-elevated trainer gets access denied reading memory.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        let _ = embed_resource::compile("trainlab-gui.rc", embed_resource::NONE);
    }
}
