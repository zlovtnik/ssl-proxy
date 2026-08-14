use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ssl_proxy::wg_packet_obfuscation::{
    decode_packet, encode_packet, WgPacketObfuscation, MAX_UDP_PACKET_SIZE,
};

fn bench_legacy_xor_max_packet(c: &mut Criterion) {
    let settings = WgPacketObfuscation::new(b"bench-obfuscation-key".to_vec(), Some(0xAA)).unwrap();
    let packet = vec![0x42; MAX_UDP_PACKET_SIZE - 1];
    let encoded = encode_packet(&packet, &settings).unwrap();

    let mut group = c.benchmark_group("wg_packet_obfuscation");
    group.bench_function("encode_legacy_xor_max_udp", |b| {
        b.iter(|| encode_packet(black_box(&packet), black_box(&settings)).unwrap());
    });
    group.bench_function("decode_legacy_xor_max_udp", |b| {
        b.iter(|| decode_packet(black_box(&encoded), black_box(&settings)).unwrap());
    });
    group.finish();
}

fn criterion_config() -> Criterion {
    Criterion::default().sample_size(20)
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = bench_legacy_xor_max_packet
}
criterion_main!(benches);
