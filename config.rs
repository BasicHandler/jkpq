use std::time::Duration;

#[derive(Debug, Clone)]
pub enum PlatformTarget {
    Android,
    Linux,
    MacOS,
    Windows,
    Unknown,
}

#[derive(Debug, Clone)]
pub enum TrustAnchor {
    PostQuantum, // The only mode now
}

#[derive(Debug, Clone)]
pub struct Config {
    pub platform: PlatformTarget,
    pub anchor: TrustAnchor,
    pub rotation_policy: RotationPolicy,
}

#[derive(Debug, Clone)]
pub struct RotationPolicy {
    pub time: Duration,
    pub volume_kb: usize,
    pub session_bound: bool,
}

pub fn initialize_module() -> Config {
    let target = std::env::var("JKPQ_BUILD_TARGET").unwrap_or_default();

    let platform = if target.contains("android") {
        PlatformTarget::Android
    } else if target.contains("linux") {
        PlatformTarget::Linux
    } else if target.contains("apple") {
        PlatformTarget::MacOS
    } else if target.contains("windows") {
        PlatformTarget::Windows
    } else {
        PlatformTarget::Unknown
    };

    Config {
        platform,
        anchor: TrustAnchor::PostQuantum, // No branching
        rotation_policy: RotationPolicy {
            time: Duration::from_secs(3600),
            volume_kb: 12800,
            session_bound: true,
        },
    }
}
