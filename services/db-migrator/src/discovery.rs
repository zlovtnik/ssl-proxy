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
    "cron",
    "materialized_views",
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
    let mut cron_files = Vec::new();
    let mut materialized_view_files = Vec::new();

    for folder in FOLDER_ORDER {
        let folder_files = collect_folder_files(sql_dir, folder, &mut result.warnings);
        match *folder {
            "cron" => cron_files = folder_files,
            "materialized_views" => materialized_view_files = folder_files,
            _ => result.files.extend(folder_files),
        }
    }

    let (pre_apply_hooks, cron_jobs): (Vec<_>, Vec<_>) = cron_files
        .into_iter()
        .partition(|file| file.name.starts_with("000_"));
    result.files.extend(pre_apply_hooks);
    result.files.extend(materialized_view_files);
    result.files.extend(cron_jobs);

    Ok(result)
}

fn collect_folder_files(sql_dir: &Path, folder: &str, warnings: &mut Vec<String>) -> Vec<SqlFile> {
    let folder_path = sql_dir.join(folder);
    if !folder_path.exists() {
        warnings.push(format!(
            "folder '{}' is missing; skipping",
            folder_path.display()
        ));
        return Vec::new();
    }
    if !folder_path.is_dir() {
        warnings.push(format!(
            "path '{}' is not a directory; skipping",
            folder_path.display()
        ));
        return Vec::new();
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

    folder_files
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .and_then(OsStr::to_str)
                .unwrap_or_default()
                .to_string();
            SqlFile {
                folder: folder.to_string(),
                path,
                name,
            }
        })
        .collect()
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

    #[test]
    fn discovery_places_cron_unschedule_before_materialized_views() -> Result<()> {
        let tmp = tempdir()?;
        let sql_dir = tmp.path().join("sql");
        fs::create_dir_all(sql_dir.join("cron"))?;
        fs::create_dir_all(sql_dir.join("materialized_views"))?;
        fs::write(
            sql_dir.join("cron").join("000_unschedule_cron_jobs.sql"),
            "select 1;",
        )?;
        fs::write(
            sql_dir.join("cron").join("001_install_cron_jobs.sql"),
            "select 1;",
        )?;
        fs::write(
            sql_dir
                .join("materialized_views")
                .join("001_refreshable_view.sql"),
            "select 1;",
        )?;

        let discovered = discover_sql_files(&sql_dir)?;
        let relative_paths: Vec<String> = discovered
            .files
            .iter()
            .map(SqlFile::relative_path)
            .collect();

        assert_eq!(
            relative_paths,
            vec![
                "cron/000_unschedule_cron_jobs.sql",
                "materialized_views/001_refreshable_view.sql",
                "cron/001_install_cron_jobs.sql",
            ]
        );
        Ok(())
    }
}
