#![no_main]
use libfuzzer_sys::fuzz_target;
use nextssl::{KdfCaps, Limits, SignAlg};
use nextssl_core::{Len, PublicKey, SymmetricKey};

// Untrusted envelope bytes (and their text form) must never panic, hang or allocate wildly:
// every decode path returns Ok or Err. Limits are small so the password path stays cheap.
fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_input: 1 << 16,
        kdf: KdfCaps {
            max_m_kib: 64,
            max_t: 2,
        },
        ..Limits::default()
    };
    let key = SymmetricKey::from_bytes(&[0x42; 32], Len::fixed(32)).unwrap();
    let _ = nextssl::decrypt_with_limits(&key, data, b"", &limits);
    let _ = nextssl::decrypt_with_password_with_limits(b"pw", data, b"", &limits);
    let pk = PublicKey::from_bytes(&[1u8; 32], Len::fixed(32)).unwrap();
    let _ = nextssl::verify_with_limits(SignAlg::Ed25519, &pk, data, b"", &limits);
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(bytes) = nextssl::from_text(text, &limits) {
            // Accepted text must be canonical: it re-encodes to exactly the same string.
            assert_eq!(nextssl::to_text(&bytes), text);
            let _ = nextssl::decrypt_with_limits(&key, &bytes, b"", &limits);
        }
    }
});
