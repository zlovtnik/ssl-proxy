use std::error::Error as StdError;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionErrorKind {
    Connection,
    Apply,
}

#[derive(Debug)]
pub struct ExecutionError {
    pub kind: ExecutionErrorKind,
    message: String,
}

impl ExecutionError {
    pub fn connection(message: impl Into<String>) -> Self {
        Self {
            kind: ExecutionErrorKind::Connection,
            message: message.into(),
        }
    }

    pub fn apply(message: impl Into<String>) -> Self {
        Self {
            kind: ExecutionErrorKind::Apply,
            message: message.into(),
        }
    }

    pub fn is_connection_failure(&self) -> bool {
        self.kind == ExecutionErrorKind::Connection
    }
}

impl Display for ExecutionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl StdError for ExecutionError {}

pub fn format_pg_error(file: &str, error: &tokio_postgres::Error) -> String {
    if let Some(db_error) = error.as_db_error() {
        let mut output = format!(
            "{file}: postgres error [{}] {}",
            db_error.code().code(),
            db_error.message()
        );
        if let Some(detail) = db_error.detail() {
            output.push_str(&format!(" | detail: {detail}"));
        }
        if let Some(hint) = db_error.hint() {
            output.push_str(&format!(" | hint: {hint}"));
        }
        output
    } else {
        format!("{file}: {error}")
    }
}
