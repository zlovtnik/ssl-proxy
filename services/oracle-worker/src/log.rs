use rdkafka::Message;

use crate::SERVICE_NAME;

pub(crate) fn error_chain(error: &dyn std::error::Error) -> String {
    let mut msg = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        msg.push_str(" | caused by: ");
        msg.push_str(&cause.to_string());
        source = cause.source();
    }
    msg
}

pub(crate) fn log_poison_message(message: &rdkafka::message::BorrowedMessage<'_>, error: &serde_json::Error) {
    let topic = escape_for_log(message.topic());
    let error = escape_for_log(&format!("deserialize OracleLoad payload: {error}"));
    eprintln!(
        "service={SERVICE_NAME} event=worker_load status=error classification=poison topic={topic} partition={} offset={} payload_bytes={} error=\"{}\"",
        message.partition(),
        message.offset(),
        message.payload().map(|payload| payload.len()).unwrap_or(0),
        error,
    );
}

pub(crate) fn escape_for_log(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' | '\r' | '\t' => escaped.push(' '),
            _ => escaped.push(ch),
        }
    }
    escaped
}
