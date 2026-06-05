use super::*;

#[test]
fn startup_channel_application_uses_configured_device_and_channel() {
    let mut called = None;

    apply_configured_channel("wlan0", 11, |device, channel| {
        called = Some((device.to_string(), channel));
        Ok::<(), ()>(())
    })
    .unwrap();

    assert_eq!(called, Some(("wlan0".to_string(), 11)));
}
