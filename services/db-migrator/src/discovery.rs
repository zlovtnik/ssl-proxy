use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use walkdir::WalkDir;

pub const FOLDER_ORDER: &[&str] = &[
    "extensions",
    "schemas",
    "types",
    "tables",
    "indexes",
    "functions",
    "views",
    "materialized_views",
    "cron",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlFile {
    pub folder: String,
    pub path: PathBuf,
    pub name: String,
}

impl SqlFile {
    pub fn relative_path(&self) -> String {
        format!("{}/{}", self.folder, self.name)
    }
}

#[derive(Debug, Default)]
pub struct DiscoveryResult {
    pub files: Vec<SqlFile>,
    pub warnings: Vec<String>,
}

pub fn discover_sql_files(sql_dir: &Path) -> Result<DiscoveryResult> {
    let mut result = DiscoveryResult::default();

    for folder in FOLDER_ORDER {
        let folder_path = sql_dir.join(folder);
        if !folder_path.exists() {
            result.warnings.push(format!(
                "folder '{}' is missing; skipping",
                folder_path.display()
            ));
            continue;
        }
        if !folder_path.is_dir() {
            result.warnings.push(format!(
                "path '{}' is not a directory; skipping",
                folder_path.display()
            ));
            continue;
        }

        let mut folder_files: Vec<PathBuf> = WalkDir::new(&folder_path)
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .map(|entry| entry.into_path())
            .filter(|path| path.extension() == Some(OsStr::new("sql")))
            .collect();

        folder_files.sort_by(|left, right| {
            let left_name = left.file_name().and_then(OsStr::to_str).unwrap_or_default();
            let right_name = right
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default();
            left_name.cmp(right_name)
        });

        for path in folder_files {
            let name = path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            result.files.push(SqlFile {
                folder: (*folder).to_string(),
                path,
                name,
            });
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn discovery_sorts_files_by_name_inside_folder() -> Result<()> {
        let tmp = tempdir()?;
        let sql_dir = tmp.path().join("sql");
        let tables_dir = sql_dir.join("tables");
        fs::create_dir_all(&tables_dir)?;
        fs::write(tables_dir.join("002_b.sql"), "select 1;")?;
        fs::write(tables_dir.join("001_a.sql"), "select 1;")?;

        let discovered = discover_sql_files(&sql_dir)?;
        let names: Vec<String> = discovered
            .files
            .iter()
            .filter(|file| file.folder == "tables")
            .map(|file| file.name.clone())
            .collect();

        assert_eq!(names, vec!["001_a.sql", "002_b.sql"]);
        Ok(())
    }

    #[test]
    fn discovery_warns_when_folder_missing() -> Result<()> {
        let tmp = tempdir()?;
        let sql_dir = tmp.path().join("sql");
        fs::create_dir_all(&sql_dir)?;

        let discovered = discover_sql_files(&sql_dir)?;
        assert!(discovered
            .warnings
            .iter()
            .any(|warning| warning.contains("extensions")));
        Ok(())
    }
}
