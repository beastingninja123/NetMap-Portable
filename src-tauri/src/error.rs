use serde::Serialize;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("invalid input: {0}")]
    Invalid(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("CSV error: {0}")]
    Csv(#[from] csv::Error),
    #[error("capture parse error: {0}")]
    Pcap(String),
}

impl Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

pub type Result<T> = std::result::Result<T, AppError>;

pub fn require_existing_file(path: &str, extensions: &[&str]) -> Result<std::path::PathBuf> {
    let path = Path::new(path);
    if !path.is_file() {
        return Err(AppError::NotFound(path.display().to_string()));
    }
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !extensions.iter().any(|allowed| *allowed == extension) {
        return Err(AppError::Invalid(format!(
            "expected one of: {}",
            extensions.join(", ")
        )));
    }
    Ok(path.to_path_buf())
}
