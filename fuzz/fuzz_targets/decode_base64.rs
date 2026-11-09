#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Strict decode must never panic; whatever it accepts must re-encode to the same text.
    if let Ok(bytes) = nextssl::decode("base64", data) {
        let again = nextssl::encode("base64", &bytes).expect("encode");
        assert_eq!(again, data, "decode accepted non-canonical input");
    }
});
