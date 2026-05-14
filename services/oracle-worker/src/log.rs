use async_nats::jetstream;

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

pub(crate) fn log_poison_message(message: &jetstream::Message, error: &serde_json::Error) {
    let subject = escape_for_log(message.subject.as_str());
    let error = escape_for_log(&format!("deserialize OracleLoad payload: {error}"));
    match message.info() {
        Ok(info) => eprintln!(
            "service={SERVICE_NAME} event=worker_load status=error classification=poison subject={subject} stream={} consumer={} stream_sequence={} consumer_sequence={} delivered={} pending={} payload_bytes={} error=\"{}\"",
            escape_for_log(info.stream),
            escape_for_log(info.consumer),
            info.stream_sequence,
            info.consumer_sequence,
            info.delivered,
            info.pending,
            message.payload.len(),
            error,
        ),
        Err(info_error) => eprintln!(
            "service={SERVICE_NAME} event=worker_load status=error classification=poison subject={subject} stream=unknown consumer=unknown stream_sequence=unknown consumer_sequence=unknown delivered=unknown pending=unknown payload_bytes={} metadata_error=\"{}\" error=\"{}\"",
            message.payload.len(),
            escape_for_log(&info_error.to_string()),
            error,
        ),
    }
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
