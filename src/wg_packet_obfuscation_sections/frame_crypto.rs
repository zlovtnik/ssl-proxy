fn apply_xor_mask(packet: &mut [u8], key: &[u8]) {
    debug_assert!(!key.is_empty(), "obfuscation key must not be empty");

    if packet.is_empty() {
        return;
    }

    if key.len() == 1 {
        let mask = key[0];
        for byte in packet {
            *byte ^= mask;
        }
        return;
    }

    if packet.len() <= key.len() {
        for (byte, mask) in packet.iter_mut().zip(key.iter()) {
            *byte ^= *mask;
        }
        return;
    }

    let mut chunks = packet.chunks_exact_mut(key.len());
    for chunk in &mut chunks {
        for (byte, mask) in chunk.iter_mut().zip(key.iter()) {
            *byte ^= *mask;
        }
    }

    for (byte, mask) in chunks.into_remainder().iter_mut().zip(key.iter()) {
        *byte ^= *mask;
    }
}
