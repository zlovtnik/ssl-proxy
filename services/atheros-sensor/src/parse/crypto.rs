//! WPA2/WPA3 cryptographic operations for PTK derivation and CCMP decryption.

use aes::Aes128;
use ccm::{
    aead::{generic_array::GenericArray, Aead, KeyInit, Payload},
    consts::{U13, U8},
    Ccm,
};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;
type Aes128Ccm = Ccm<Aes128, U8, U13>;

/// Derives PTK from PSK, SSID, nonces, and MAC addresses.
/// Returns (KCK, KEK, TK) as three 16-byte arrays.
pub fn derive_ptk(
    psk: &str,
    ssid: &str,
    anonce: &[u8; 32],
    snonce: &[u8; 32],
    bssid: &[u8; 6],
    client_mac: &[u8; 6],
) -> ([u8; 16], [u8; 16], [u8; 16]) {
    let pmk = derive_pmk(psk, ssid);
    let mut prf_input = Vec::with_capacity(76);
    prf_input.extend_from_slice(b"Pairwise key expansion\0");
    
    let (min_mac, max_mac) = if bssid < client_mac {
        (bssid, client_mac)
    } else {
        (client_mac, bssid)
    };
    prf_input.extend_from_slice(min_mac);
    prf_input.extend_from_slice(max_mac);
    
    let (min_nonce, max_nonce) = if anonce < snonce {
        (anonce, snonce)
    } else {
        (snonce, anonce)
    };
    prf_input.extend_from_slice(min_nonce);
    prf_input.extend_from_slice(max_nonce);
    
    let ptk = prf_512(&pmk, &prf_input);
    
    let mut kck = [0u8; 16];
    let mut kek = [0u8; 16];
    let mut tk = [0u8; 16];
    kck.copy_from_slice(&ptk[0..16]);
    kek.copy_from_slice(&ptk[16..32]);
    tk.copy_from_slice(&ptk[32..48]);
    
    (kck, kek, tk)
}

fn derive_pmk(psk: &str, ssid: &str) -> [u8; 32] {
    let mut pmk = [0u8; 32];
    pbkdf2_hmac::<Sha1>(psk.as_bytes(), ssid.as_bytes(), 4096, &mut pmk);
    pmk
}

fn prf_512(key: &[u8; 32], data: &[u8]) -> [u8; 64] {
    let mut result = [0u8; 64];
    for i in 0..2 {
        let mut mac = <HmacSha1 as KeyInit>::new_from_slice(key).expect("HMAC key size");
        mac.update(data);
        mac.update(&[i]);
        let hash = mac.finalize().into_bytes();
        result[i * 32..(i + 1) * 32].copy_from_slice(&hash[..20]);
        if i == 0 {
            result[20..32].copy_from_slice(&hash[..12]);
        } else {
            result[52..64].copy_from_slice(&hash[..12]);
        }
    }
    result
}

/// Decrypts CCMP-encrypted payload using the temporal key.
pub fn ccmp_decrypt(
    tk: &[u8; 16],
    mpdu_header: &[u8],
    encrypted_payload: &[u8],
) -> Option<Vec<u8>> {
    if encrypted_payload.len() < 16 {
        return None;
    }
    
    let pn = extract_pn(encrypted_payload)?;
    let ciphertext = &encrypted_payload[8..encrypted_payload.len() - 8];
    let mic = &encrypted_payload[encrypted_payload.len() - 8..];
    
    let aad = build_aad(mpdu_header)?;
    let nonce = build_nonce(mpdu_header, &pn)?;
    
    let key = GenericArray::from_slice(tk);
    let cipher = Aes128Ccm::new(key);
    let nonce_ga = GenericArray::from_slice(&nonce);
    
    let mut ciphertext_with_mic = Vec::with_capacity(ciphertext.len() + mic.len());
    ciphertext_with_mic.extend_from_slice(ciphertext);
    ciphertext_with_mic.extend_from_slice(mic);
    
    let payload = Payload {
        msg: &ciphertext_with_mic,
        aad: &aad,
    };
    
    cipher.decrypt(nonce_ga, payload).ok()
}

fn extract_pn(encrypted_payload: &[u8]) -> Option<[u8; 6]> {
    if encrypted_payload.len() < 8 {
        return None;
    }
    Some([
        encrypted_payload[7],
        encrypted_payload[6],
        encrypted_payload[5],
        encrypted_payload[4],
        encrypted_payload[1],
        encrypted_payload[0],
    ])
}

fn build_aad(mpdu_header: &[u8]) -> Option<Vec<u8>> {
    if mpdu_header.len() < 24 {
        return None;
    }
    
    let mut aad = Vec::with_capacity(22);
    let fc = u16::from_le_bytes([mpdu_header[0], mpdu_header[1]]);
    let fc_masked = fc & 0x8fcf;
    aad.extend_from_slice(&fc_masked.to_le_bytes());
    aad.extend_from_slice(&mpdu_header[4..22]);
    
    Some(aad)
}

fn build_nonce(mpdu_header: &[u8], pn: &[u8; 6]) -> Option<[u8; 13]> {
    if mpdu_header.len() < 24 {
        return None;
    }
    
    let mut nonce = [0u8; 13];
    nonce[0] = 0x00;
    
    let fc = u16::from_le_bytes([mpdu_header[0], mpdu_header[1]]);
    let to_ds = fc & (1 << 8) != 0;
    let from_ds = fc & (1 << 9) != 0;
    
    let source_mac = match (to_ds, from_ds) {
        (false, false) => &mpdu_header[10..16],
        (true, false) => &mpdu_header[10..16],
        (false, true) => &mpdu_header[16..22],
        (true, true) => {
            if mpdu_header.len() >= 30 {
                &mpdu_header[24..30]
            } else {
                return None;
            }
        }
    };
    
    nonce[1..7].copy_from_slice(source_mac);
    nonce[7..13].copy_from_slice(pn);
    
    Some(nonce)
}

pub fn parse_mac(mac_str: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = mac_str.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).ok()?;
    }
    Some(mac)
}
