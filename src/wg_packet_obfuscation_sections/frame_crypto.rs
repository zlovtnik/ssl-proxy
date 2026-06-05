fn apply_xor_mask(packet: &mut [u8], key: &[u8]) {
    debug_assert!(!key.is_empty(), "obfuscation key must not be empty");
    for (index, byte) in packet.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}
