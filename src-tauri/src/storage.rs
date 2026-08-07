use crate::error::{AppError, Result};
use crate::models::{ProjectInfo, TestCapture};
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

    pub fn list_test_captures(&self) -> Result<Vec<TestCapture>> {
        let root = if self.portable {
            std::env::current_exe()?
                .parent()
                .ok_or_else(|| AppError::Invalid("the executable has no parent directory".into()))?
                .join("test-pcaps")
        } else {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .parent()
                .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
                .join("test-pcaps")
        };
        let catalog = [
            (
                "netresec-4sics-geek-lounge-2015-10-20",
                "4SICS Multi-Host ICS Lab",
                "15 IP hosts, 246k packets, 24.5 MB. Real PLC, RTU, gateway, firewall, switch, and workstation lab traffic.",
                &["S7COMM", "TCP", "UDP", "DNS"][..],
            ),
            (
                "netresec-s4x15-bacnet-fiu",
                "S4x15 Multi-Host BACnet Lab",
                "12 IP hosts, 101k packets, 10.2 MB. Real BACnet Internet and supporting ICS Village traffic.",
                &["BACNET", "TCP", "UDP", "HTTP"][..],
            ),
            (
                "wireshark-modbus-tcp-float",
                "Real Modbus/TCP Session",
                "Wireshark capture of Modbus/TCP floating-point register traffic.",
                &["MODBUS"][..],
            ),
            (
                "wireshark-s7comm-plc-status",
                "Real S7 PLC Status Session",
                "Wireshark capture of a client connecting to and reading Siemens S7-300 PLC status.",
                &["S7COMM"][..],
            ),
            (
                "wireshark-dnp3-select-operate",
                "Real DNP3 Select/Operate",
                "Wireshark DNP3 control sequence originally sourced from pcapr.net.",
                &["DNP3"][..],
            ),
            (
                "wireshark-iec104",
                "Real IEC 104 Communication",
                "Wireshark IEC 60870-5-104 communication log.",
                &["IEC 104"][..],
            ),
            (
                "wireshark-hart-ip",
                "Real HART-IP Sessions",
                "Wireshark capture containing both HART-IP UDP and TCP sessions.",
                &["HART-IP"][..],
            ),
        ];
        catalog
            .into_iter()
            .map(|(id, name, description, protocols)| {
                let path = root.join(format!("{id}.pcap"));
                if !path.is_file() {
                    return Err(AppError::NotFound(format!(
                        "bundled test capture {}",
                        path.display()
                    )));
                }
                Ok(TestCapture {
                    id: id.into(),
                    name: name.into(),
                    description: description.into(),
                    protocols: protocols.iter().map(|value| (*value).into()).collect(),
                    path: path.display().to_string(),
                })
            })
            .collect()
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

    #[test]
    fn bundled_test_capture_catalog_resolves_local_files() {
        let root = std::env::temp_dir().join(format!("netmap-tests-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let storage = Storage {
            root: root.clone(),
            portable: false,
        };
        let captures = storage.list_test_captures().unwrap();
        assert_eq!(captures.len(), 7);
        assert!(captures
            .iter()
            .all(|capture| Path::new(&capture.path).is_file()));
        assert!(captures
            .iter()
            .any(|capture| capture.id == "wireshark-modbus-tcp-float"));
        assert!(captures
            .iter()
            .any(|capture| capture.id == "netresec-4sics-geek-lounge-2015-10-20"));
        let _ = fs::remove_dir_all(&root);
    }
}
