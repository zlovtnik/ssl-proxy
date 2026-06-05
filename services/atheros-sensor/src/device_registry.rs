//! Device registry MAC lookup cache and retry backoff.

use std::{num::NonZeroUsize, time::Duration, time::Instant};

use lru::LruCache;

pub type DeviceRegistryLookup = (String, Option<String>);

pub struct DeviceRegistryCache {
    device_cache: LruCache<String, Option<DeviceRegistryLookup>>,
    error_cache: LruCache<String, Instant>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceRegistryCacheDecision {
    UseCached(Option<DeviceRegistryLookup>),
    SkipRecentFailure,
    Fetch,
}

impl DeviceRegistryCache {
    pub fn new(capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity)
            .unwrap_or_else(|| NonZeroUsize::new(1).expect("cache capacity must be non-zero"));
        Self {
            device_cache: LruCache::new(capacity),
            error_cache: LruCache::new(capacity),
        }
    }

    pub fn lookup_decision(
        &mut self,
        cache_key: &str,
        error_ttl: Duration,
    ) -> DeviceRegistryCacheDecision {
        if let Some(cached) = self.device_cache.get(cache_key) {
            return DeviceRegistryCacheDecision::UseCached(cached.clone());
        }
        if self
            .error_cache
            .get(cache_key)
            .is_some_and(|last| last.elapsed() < error_ttl)
        {
            return DeviceRegistryCacheDecision::SkipRecentFailure;
        }
        DeviceRegistryCacheDecision::Fetch
    }

    pub fn remember_success(&mut self, cache_key: String, lookup: Option<DeviceRegistryLookup>) {
        self.error_cache.pop(&cache_key);
        self.device_cache.put(cache_key, lookup);
    }

    pub fn remember_failure(&mut self, cache_key: String) {
        self.error_cache.put(cache_key, Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn failure_suppresses_retry_without_caching_miss() {
        let mut cache = DeviceRegistryCache::new(4);
        let cache_key = "aa:bb:cc:dd:ee:ff".to_string();

        cache.remember_failure(cache_key.clone());

        assert_eq!(
            cache.lookup_decision(&cache_key, Duration::from_secs(30)),
            DeviceRegistryCacheDecision::SkipRecentFailure
        );
        assert!(cache.device_cache.get(&cache_key).is_none());
    }

    #[test]
    fn success_caches_none_and_clears_error_backoff() {
        let mut cache = DeviceRegistryCache::new(4);
        let cache_key = "aa:bb:cc:dd:ee:ff".to_string();
        cache.remember_failure(cache_key.clone());

        cache.remember_success(cache_key.clone(), None);

        assert_eq!(
            cache.lookup_decision(&cache_key, Duration::from_secs(30)),
            DeviceRegistryCacheDecision::UseCached(None)
        );
        assert!(cache.error_cache.get(&cache_key).is_none());
    }
}
