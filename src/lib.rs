pub mod control;
pub mod network;

pub fn executable(candidates: &[&str]) -> anyhow::Result<std::path::PathBuf> {
    use anyhow::Context;
    candidates
        .iter()
        .map(std::path::PathBuf::from)
        .find(|path| path.is_file())
        .with_context(|| format!("Required executable not found: {}", candidates.join(", ")))
}

#[cfg(feature = "tray")]
pub mod tray;
