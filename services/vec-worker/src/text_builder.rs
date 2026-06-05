//! Text content builder - maps an `EmbeddingJob` to its embedding text and metadata.
//!
//! This module mirrors the Ruby `VectorEmbeddings::TextBuilder` reference implementation.
//! Each supported `embedding_kind` has a dedicated build
//! function that queries the source table and produces identity-stripped semantic text
//! plus associated metadata for the `EmbeddingInput`.

#[cfg(test)]
#[path = "text_builder_tests.rs"]
mod tests;

include!("text_builder_sections/common_events.rs");
include!("text_builder_sections/devices_behaviour.rs");
include!("text_builder_sections/profiles_sequences.rs");
include!("text_builder_sections/timing_infra.rs");
include!("text_builder_sections/formatting.rs");
