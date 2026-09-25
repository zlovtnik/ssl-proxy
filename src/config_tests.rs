use crate::wg_packet_obfuscation::{
    EncryptionMode, PacketPadding, AEAD_TAG_LEN_BYTES, FRAMED_BODY_LEN_FIELD_LEN, FRAMED_HEADER_LEN,
};

include!("config_test_sections/proxy_wireguard.rs");
include!("config_test_sections/sync_payload.rs");
