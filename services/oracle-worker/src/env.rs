use std::env;

pub(crate) fn required_env(name: &str) -> Result<String, String> {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("missing required env: {name}")),
    }
}

pub(crate) fn env_or_default(name: &str, default: &str) -> String {
    match env::var(name) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => default.to_string(),
    }
}

pub(crate) fn env_or_default_usize(name: &str, default: usize) -> usize {
    match env::var(name) {
        Ok(value) => value.trim().parse::<usize>().unwrap_or(default),
        _ => default,
    }
}

#[cfg(test)]
mod tests {
    use super::env_or_default;

    #[test]
    fn env_or_default_uses_fallback_for_blank_values() {
        let key = format!("OW_TEST_FALLBACK_{}", std::process::id());
        std::env::set_var(&key, "");
        assert_eq!(env_or_default(&key, "fallback"), "fallback");
        std::env::remove_var(&key);
    }
}
