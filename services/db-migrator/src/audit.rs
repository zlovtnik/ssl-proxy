use std::fs;

use crate::discovery::SqlFile;

const TABLE_COLUMN_WARNING_LIMIT: usize = 15;

#[derive(Debug, Default)]
pub struct ValidationReport {
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

impl ValidationReport {
    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }
}

pub fn validate_sql_files(files: &[SqlFile]) -> ValidationReport {
    let mut report = ValidationReport::default();

    for file in files {
        let sql = match fs::read_to_string(&file.path) {
            Ok(sql) => sql,
            Err(error) => {
                report.errors.push(format!(
                    "{}: unreadable SQL file ({error})",
                    file.relative_path()
                ));
                continue;
            }
        };

        if sql.trim().is_empty() {
            report
                .errors
                .push(format!("{}: SQL file is empty", file.relative_path()));
            continue;
        }

        if let Err(parse_error) = check_balanced_sql(&sql) {
            report.errors.push(format!(
                "{}: SQL parsing check failed ({parse_error})",
                file.relative_path()
            ));
            continue;
        }

        if !has_header(&sql) {
            report.errors.push(format!(
                "{}: missing required header comments (-- object, -- folder, -- depends_on)",
                file.relative_path()
            ));
            continue;
        }

        apply_folder_heuristics(&mut report, file, &sql);
    }

    report
}

fn has_header(sql: &str) -> bool {
    let lower = sql.to_lowercase();
    lower.contains("-- object:") && lower.contains("-- folder:") && lower.contains("-- depends_on:")
}

fn apply_folder_heuristics(report: &mut ValidationReport, file: &SqlFile, sql: &str) {
    let lower = sql.to_lowercase();
    let path = file.relative_path();

    match file.folder.as_str() {
        "tables" => {
            if !lower.contains("create table if not exists") {
                report.warnings.push(format!(
                    "{path}: expected 'CREATE TABLE IF NOT EXISTS' for idempotency"
                ));
            }
            if let Some(column_count) = create_table_column_count(sql) {
                if column_count > TABLE_COLUMN_WARNING_LIMIT {
                    report.warnings.push(format!(
                        "{path}: table has {column_count} columns; prefer <= {TABLE_COLUMN_WARNING_LIMIT} columns and vertical partitioning for hot-path schemas"
                    ));
                }
            }
        }
        "functions" => {
            if !lower.contains("create or replace function") {
                report.warnings.push(format!(
                    "{path}: expected 'CREATE OR REPLACE FUNCTION' for idempotency"
                ));
            }
        }
        "views" => {
            let has_replace = lower.contains("create or replace view");
            let has_drop_create =
                lower.contains("drop view if exists") && lower.contains("create view");
            if !(has_replace || has_drop_create) {
                report.warnings.push(format!(
                    "{path}: expected 'CREATE OR REPLACE VIEW' or 'DROP VIEW IF EXISTS' + 'CREATE VIEW'"
                ));
            }
        }
        "indexes" => {
            let has_index = lower.contains("create index if not exists")
                || lower.contains("create unique index if not exists");
            if !has_index {
                report.warnings.push(format!(
                    "{path}: expected 'CREATE INDEX IF NOT EXISTS' or 'CREATE UNIQUE INDEX IF NOT EXISTS'"
                ));
            }
        }
        "extensions" => {
            if !lower.contains("create extension if not exists") {
                report
                    .warnings
                    .push(format!("{path}: expected 'CREATE EXTENSION IF NOT EXISTS'"));
            }
        }
        _ => {}
    }
}

fn create_table_column_count(sql: &str) -> Option<usize> {
    let lower = sql.to_lowercase();
    let create_pos = lower.find("create table")?;
    let open_relative = sql[create_pos..].find('(')?;
    let open = create_pos + open_relative;
    let close = matching_close_paren(sql, open)?;
    let body = &sql[open + 1..close];

    Some(
        split_top_level_commas(body)
            .into_iter()
            .filter(|part| is_column_definition(part))
            .count(),
    )
}

fn matching_close_paren(sql: &str, open: usize) -> Option<usize> {
    let bytes = sql.as_bytes();
    let mut index = open;
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);

        if in_single {
            if ch == '\'' && next == Some('\'') {
                index += 2;
                continue;
            }
            if ch == '\'' {
                in_single = false;
            }
            index += 1;
            continue;
        }

        if in_double {
            if ch == '"' {
                in_double = false;
            }
            index += 1;
            continue;
        }

        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }

    None
}

fn split_top_level_commas(body: &str) -> Vec<&str> {
    let bytes = body.as_bytes();
    let mut parts = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut depth = 0usize;
    let mut in_single = false;
    let mut in_double = false;

    while index < bytes.len() {
        let ch = bytes[index] as char;
        let next = bytes.get(index + 1).copied().map(char::from);

        if in_single {
            if ch == '\'' && next == Some('\'') {
                index += 2;
                continue;
            }
            if ch == '\'' {
                in_single = false;
            }
            index += 1;
            continue;
        }

        if in_double {
            if ch == '"' {
                in_double = false;
            }
            index += 1;
            continue;
        }

        match ch {
            '\'' => in_single = true,
            '"' => in_double = true,
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(body[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }

        index += 1;
    }

    let tail = body[start..].trim();
    if !tail.is_empty() {
        parts.push(tail);
    }
    parts
}

fn is_column_definition(part: &str) -> bool {
    let first = part
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .to_ascii_lowercase();

    !matches!(
        first.as_str(),
        "" | "constraint" | "primary" | "foreign" | "unique" | "check" | "exclude"
    )
}

fn check_balanced_sql(sql: &str) -> Result<(), String> {
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    let mut in_single = false;
    let mut in_double = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut dollar_tag: Option<Vec<u8>> = None;

    while i < bytes.len() {
        let ch = bytes[i] as char;
        let next = if i + 1 < bytes.len() {
            bytes[i + 1] as char
        } else {
            '\0'
        };

        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
            }
            i += 1;
            continue;
        }

        if in_block_comment {
            if ch == '*' && next == '/' {
                in_block_comment = false;
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }

        if let Some(tag) = dollar_tag.as_ref() {
            if bytes[i..].starts_with(tag) {
                i += tag.len();
                dollar_tag = None;
                continue;
            }
            i += 1;
            continue;
        }

        if in_single {
            if ch == '\'' && next == '\'' {
                i += 2;
                continue;
            }
            if ch == '\'' {
                in_single = false;
            }
            i += 1;
            continue;
        }

        if in_double {
            if ch == '"' {
                in_double = false;
            }
            i += 1;
            continue;
        }

        if ch == '-' && next == '-' {
            in_line_comment = true;
            i += 2;
            continue;
        }
        if ch == '/' && next == '*' {
            in_block_comment = true;
            i += 2;
            continue;
        }
        if ch == '\'' {
            in_single = true;
            i += 1;
            continue;
        }
        if ch == '"' {
            in_double = true;
            i += 1;
            continue;
        }
        if ch == '$' {
            if let Some(tag) = parse_dollar_tag(bytes, i) {
                i += tag.len();
                dollar_tag = Some(tag);
                continue;
            }
        }

        i += 1;
    }

    if in_single {
        return Err("unterminated single-quoted string".to_string());
    }
    if in_double {
        return Err("unterminated double-quoted identifier".to_string());
    }
    if in_block_comment {
        return Err("unterminated block comment".to_string());
    }
    if let Some(tag) = dollar_tag {
        let tag_display = String::from_utf8_lossy(&tag);
        return Err(format!(
            "unterminated dollar-quoted block with tag {tag_display}"
        ));
    }

    Ok(())
}

fn parse_dollar_tag(bytes: &[u8], start: usize) -> Option<Vec<u8>> {
    if bytes.get(start).copied() != Some(b'$') {
        return None;
    }
    let mut index = start + 1;
    while index < bytes.len() {
        let ch = bytes[index] as char;
        if ch == '$' {
            return Some(bytes[start..=index].to_vec());
        }
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return None;
        }
        index += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    fn sql_file(folder: &str, name: &str, path: PathBuf) -> SqlFile {
        SqlFile {
            folder: folder.to_string(),
            path,
            name: name.to_string(),
        }
    }

    #[test]
    fn validate_flags_non_idempotent_table() {
        let tmp = tempdir().expect("tempdir");
        let file_path = tmp.path().join("001_table.sql");
        fs::write(
            &file_path,
            "-- object: sample\n-- folder: tables\n-- depends_on: -\ncreate table foo(id int);\n",
        )
        .expect("write");

        let report = validate_sql_files(&[sql_file("tables", "001_table.sql", file_path)]);
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("CREATE TABLE IF NOT EXISTS")));
        assert!(!report.has_errors());
    }

    #[test]
    fn validate_errors_when_required_header_is_missing() {
        let tmp = tempdir().expect("tempdir");
        let file_path = tmp.path().join("001_table.sql");
        fs::write(&file_path, "create table if not exists foo(id int);\n").expect("write");

        let report = validate_sql_files(&[sql_file("tables", "001_table.sql", file_path)]);

        assert!(report.has_errors());
        assert!(report
            .errors
            .iter()
            .any(|error| error.contains("missing required header")));
    }

    #[test]
    fn validate_warns_for_wide_table() {
        let tmp = tempdir().expect("tempdir");
        let file_path = tmp.path().join("001_table.sql");
        fs::write(
            &file_path,
            "-- object: sample\n-- folder: tables\n-- depends_on: -\ncreate table if not exists foo(\n  c01 int, c02 int, c03 int, c04 int,\n  c05 int, c06 int, c07 int, c08 int,\n  c09 int, c10 int, c11 int, c12 int,\n  c13 int, c14 int, c15 int, c16 int\n);\n",
        )
        .expect("write");

        let report = validate_sql_files(&[sql_file("tables", "001_table.sql", file_path)]);

        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("table has 16 columns")));
        assert!(!report.has_errors());
    }
}
