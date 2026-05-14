use crate::worker::resolve_payload;

use super::support::{inline_payload, unique_test_name, ENV_LOCK};

#[test]
fn resolves_inline_payloads() {
    assert_eq!(
        resolve_payload(&inline_payload(r#"{"ok":true}"#)).unwrap(),
        r#"{"ok":true}"#
    );
}

#[test]
fn rejects_outbox_path_traversal() {
    let _guard = ENV_LOCK.get_or_init(Default::default).lock().unwrap();
    let root = std::env::temp_dir().join(unique_test_name("oracle-worker-outbox"));
    let base = root.join("base");
    std::fs::create_dir_all(&base).unwrap();
    std::fs::write(root.join("escape.json"), "{}").unwrap();
    std::env::set_var("SYNC_OUTBOX_DIR", &base);

    let error = resolve_payload("outbox://../escape.json").unwrap_err();

    std::env::remove_var("SYNC_OUTBOX_DIR");
    std::fs::remove_dir_all(&root).unwrap();
    assert!(error.contains("invalid outbox path escapes base"));
}
