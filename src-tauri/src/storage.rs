use crate::error::{AppError, Result};
use crate::models::ProjectInfo;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Storage {
    root: PathBuf,
    portable: bool,
}

impl Storage {
    pub fn discover() -> Result<Self> {
        let (root, portable) = if cfg!(debug_assertions) {
            (
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .parent()
                    .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
                    .join(".netmap-data")
                    .join("projects"),
                false,
            )
        } else {
            let executable = std::env::current_exe()?;
            let directory = executable.parent().ok_or_else(|| {
                AppError::Invalid("the executable has no parent directory".into())
            })?;
            (directory.join("data").join("projects"), true)
        };
        fs::create_dir_all(&root)?;
        Ok(Self { root, portable })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn is_portable(&self) -> bool {
        self.portable
    }

    pub fn create_project(&self, name: &str) -> Result<ProjectInfo> {
        let id = sanitize_project_id(name)?;
        let directory = self.root.join(&id);
        fs::create_dir_all(directory.join("exports"))?;
        let display_name = name.trim();
        fs::write(directory.join("name.txt"), display_name)?;
        crate::db::open(&directory.join("netmap.sqlite3"))?;
        Ok(self.info(&id, display_name))
    }

    pub fn open_project(&self, id: &str) -> Result<ProjectInfo> {
        validate_project_id(id)?;
        let directory = self.root.join(id);
        if !directory.is_dir() {
            return Err(AppError::NotFound(format!("project {id}")));
        }
        let name = fs::read_to_string(directory.join("name.txt"))
            .unwrap_or_else(|_| id.to_string())
            .trim()
            .to_string();
        crate::db::open(&directory.join("netmap.sqlite3"))?;
        Ok(self.info(id, &name))
    }

    pub fn rename_project(&self, id: &str, name: &str) -> Result<ProjectInfo> {
        validate_project_id(id)?;
        let display_name = name.trim();
        if display_name.is_empty() || display_name.len() > 120 {
            return Err(AppError::Invalid(
                "project name must be between 1 and 120 characters".into(),
            ));
        }
        let directory = self.root.join(id);
        if !directory.is_dir() {
            return Err(AppError::NotFound(format!("project {id}")));
        }
        fs::write(directory.join("name.txt"), display_name)?;
        Ok(self.info(id, display_name))
    }

    pub fn list_projects(&self) -> Result<Vec<ProjectInfo>> {
        let mut projects = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            if validate_project_id(&id).is_ok() {
                let name = fs::read_to_string(entry.path().join("name.txt"))
                    .unwrap_or_else(|_| id.clone())
                    .trim()
                    .to_string();
                projects.push(self.info(&id, &name));
            }
        }
        projects.sort_by(|left, right| left.name.to_lowercase().cmp(&right.name.to_lowercase()));
        Ok(projects)
    }

    pub fn database_path(&self, id: &str) -> Result<PathBuf> {
        validate_project_id(id)?;
        let project = self.root.join(id);
        if !project.is_dir() {
            return Err(AppError::NotFound(format!("project {id}")));
        }
        Ok(project.join("netmap.sqlite3"))
    }

    pub fn export_path(&self, id: &str, filename: &str) -> Result<PathBuf> {
        let database = self.database_path(id)?;
        let exports = database
            .parent()
            .expect("database path always has a parent")
            .join("exports");
        fs::create_dir_all(&exports)?;
        let safe = sanitize_filename(filename)?;
        Ok(exports.join(safe))
    }

    fn info(&self, id: &str, name: &str) -> ProjectInfo {
        ProjectInfo {
            id: id.to_string(),
            name: name.to_string(),
            path: self.root.join(id).display().to_string(),
        }
    }
}

fn sanitize_project_id(name: &str) -> Result<String> {
    let value = name
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '-' || character == '_' {
                character
            } else {
                '-'
            }
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    validate_project_id(&value)?;
    Ok(value)
}

fn validate_project_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id.len() > 80
        || !id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_".contains(character))
    {
        return Err(AppError::Invalid("invalid project identifier".into()));
    }
    Ok(())
}

fn sanitize_filename(filename: &str) -> Result<String> {
    let basename = Path::new(filename)
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| AppError::Invalid("invalid export filename".into()))?;
    let stem = basename.strip_suffix(".csv").unwrap_or(basename);
    if stem.is_empty()
        || stem.len() > 100
        || !stem
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_ ".contains(character))
    {
        return Err(AppError::Invalid("invalid export filename".into()));
    }
    Ok(format!("{stem}.csv"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_ids_are_safe_and_predictable() {
        assert_eq!(
            sanitize_project_id(" Lab Network 2026 ").unwrap(),
            "lab-network-2026"
        );
        assert_eq!(sanitize_project_id("../../escape").unwrap(), "escape");
    }

    #[test]
    fn export_names_cannot_escape() {
        assert_eq!(sanitize_filename("../flows.csv").unwrap(), "flows.csv");
        assert!(sanitize_filename("bad.name.csv").is_err());
    }

    #[test]
    fn rename_updates_display_name_file() {
        let root = std::env::temp_dir().join(format!("netmap-rename-{}", uuid::Uuid::new_v4()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let storage = Storage {
            root: root.clone(),
            portable: false,
        };
        let project = storage.create_project("Original Name").unwrap();
        let renamed = storage.rename_project(&project.id, "Renamed Case").unwrap();
        assert_eq!(renamed.name, "Renamed Case");
        assert_eq!(
            fs::read_to_string(root.join(&project.id).join("name.txt"))
                .unwrap()
                .trim(),
            "Renamed Case"
        );
        let _ = fs::remove_dir_all(&root);
    }
}
