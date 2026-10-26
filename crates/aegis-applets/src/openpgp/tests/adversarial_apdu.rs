//! Adversarial APDU suite for the decipher and the D2 provisioning paths.
//!
//! The suite pins the closed-error contract of the data-heavy commands per
//! `specs/openpgp-apdu-adversarial-tests.md`: every malformed `PSO: DECIPHER`
//! frame and every out-of-domain `PUT DATA D2` body answers one deterministic
//! status word with an empty body, no panic, no save and no state change. The
//! anti-serialization check of the invariant (no answer may echo private key
//! material, the wrapped session key or a shared secret off its documented
//! route) lives inside the tests, next to the refusals it guards.

use super::*;
use std::vec::Vec;

/// Generate a session key for fixture provisioning.
pub(crate) fn session_key(rng: &mut impl rand_core::RngCore) -> [u8; 16] {
    let mut key = [0u8; 16];
    rng.fill_bytes(&mut key);
    key
}

/// The ephemeral scalar of the sender in the fixture provisioning.
pub(crate) const EPHEMERAL_SCALAR: [u8; 32] = [9u8; 32];

/// Cipher DOs shorter than the framing needs (`A6` declared longer than the
/// data that follows). On the RSA path the reader degrades the truncated TLV
/// to the raw input, which `rsa_cipher_block` then refuses: both etiologies
/// end in the same closed status word.
const TRUNCATED_A6: &[u8] = &[0xA6, 0x03, 0x86, 0x02, 0x41];
/// An empty `86` value inside the cipher DO: no point at all.
const EMPTY_86: &[u8] = &[0xA6, 0x02, 0x86, 0x00];
/// A TLV whose long-form length runs past the end of the data.
const LONG_LENGTH: &[u8] = &[0xA6, 0x03, 0x86, 0x81, 0x40];
/// A bare top-level `86` whose long-form length runs past the data.
const LONG_INNER_86: &[u8] = &[0x86, 0x81, 0x40];
/// The structural refusals shared by the RSA, ECDH P-256 and X25519 paths.
const STRUCTURAL_REFUSALS: [&[u8]; 4] = [TRUNCATED_A6, EMPTY_86, LONG_LENGTH, LONG_INNER_86];

/// The all-zero point: not a valid SEC1 form and not on any curve.
const ZERO_POINT: [u8; 65] = [0x00; 65];
/// The SEC1 encoding of the point at infinity.
const INFINITY_POINT: [u8; 65] = {
    let mut point = [0u8; 65];
    point[0] = 0x04;
    point
};
/// An arbitrary binary point: well-formed DOC shape, off the curve.
const OFF_CURVE_POINT: [u8; 65] = {
    let mut point = [0x11u8; 65];
    point[0] = 0x04;
    point
};
/// A cipher body that exists but decrypts to nothing meaningful.
const FOREIGN_CIPHER: [u8; 8] = [0xAA; 8];

/// `tag || length || value` with the definite length the value needs.
fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if value.len() < 0x80 {
        out.push(value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x81);
        out.push(value.len() as u8);
    } else {
        out.push(0x82);
        out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(value);
    out
}

/// The command shape of a decipher: the sender point (`86`) and, when
/// present, the encrypted data (`80`).
pub(crate) fn point_command(point: &[u8], cipher: Option<&[u8]>) -> Vec<u8> {
    let mut out = tlv(0x86, point);
    if let Some(cipher) = cipher {
        out.extend_from_slice(&tlv(0x80, cipher));
    }
    out
}

/// A case-3E frame, for command bodies beyond the card's short-APDU limit.
fn extended_frame(ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut out = vec![0x00, ins, p1, p2, 0x00, (len >> 8) as u8, len as u8];
    out.extend_from_slice(data);
    out
}

/// The SEC1 bytes of the fixture ephemeral point.
pub(crate) fn fixture_ephemeral_point() -> Vec<u8> {
    use p256::elliptic_curve::sec1::ToSec1Point as _;
    let ephemeral = p256::SecretKey::from_slice(&EPHEMERAL_SCALAR).unwrap();
    ephemeral
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}

/// The material that no refusal may ever echo back: the private scalar of the
/// decryption slot and, when provisioned on it, the wrapped session key.
fn leak_sources<S: OpenPgpStore>(applet: &OpenPgp<S>) -> Vec<Vec<u8>> {
    let mut sources = vec![applet.keys[1].material[..32].to_vec()];
    if let Some(material) = applet.ecdh_material() {
        sources.push(material.wrapped.as_slice().to_vec());
    }
    sources
}

/// No window of the answer may reproduce a leak source (AC-6). The released
/// `Z` of the documented partial decrypt is passed as `documented` and
/// thereby excluded: it leaves the card on that route by design.
fn assert_never_leaks<S: OpenPgpStore>(
    response: &[u8],
    applet: &OpenPgp<S>,
    documented: Option<&[u8]>,
) {
    let mut sources = leak_sources(applet);
    if let Some(z) = documented {
        sources.retain(|source| source.as_slice() != z);
    }
    for source in &sources {
        if response.len() >= source.len() {
            assert!(
                !response
                    .windows(source.len())
                    .any(|window| window == source),
                "the refused answer leaks private or ciphertext material"
            );
        }
    }
}

/// An applet with an ECDH P-256 decryption key whose RFC 6637 material wraps
/// [`SESSION_KEY`] under the KEK the card itself derives: the card can unwrap
/// it. Returns the card point of the decryption key (the `86` DO of
/// `GENERATE`) so tests build expected values independently of the applet.
pub(crate) fn ecdh_p256_applet(seed: u64) -> (OpenPgp<MemoryOpenPgpStore>, TestRng, [u8; 65]) {
    ecdh_p256_applet_over(MemoryOpenPgpStore::new(), seed)
}

/// The same fixture over a store the caller supplies, so a test that counts
/// the saves (or failures) the provisioning performs can sit inside the same
/// session.
fn ecdh_p256_applet_over<S: OpenPgpStore>(store: S, seed: u64) -> (OpenPgp<S>, TestRng, [u8; 65]) {
    let mut applet = OpenPgp::new(store);
    assert_eq!(applet.select().sw, Sw::OK);
    let mut rng = TestRng(seed);
    verify_pw3(&mut applet, &mut rng);
    let public = generate(&mut applet, &mut rng, 0xB8);
    let card_point = tlv::find(tlv::find(&public, 0x7F49).unwrap(), 0x86).unwrap();
    assert_eq!(card_point.len(), 65, "the decryption key is a P-256 point");
    let mut point = [0u8; 65];
    point.copy_from_slice(card_point);

    let ephemeral = p256::SecretKey::from_slice(&EPHEMERAL_SCALAR).unwrap();
    let card_public = p256::PublicKey::from_sec1_bytes(&point).unwrap();
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine());
    let fingerprint = applet.fingerprint(1).expect("the slot has a fingerprint");
    let param = ecdh::param(
        ecdh::CURVE_OID_P256,
        ecdh::ALG_ECDH,
        ecdh::HASH_SHA256,
        ecdh::KEK_AES128,
        &fingerprint,
    )
    .unwrap();
    let kek = ecdh::kdf(&param, shared.raw_secret_bytes().as_slice(), 16).unwrap();

    let checksum = SESSION_KEY
        .iter()
        .fold(0u16, |acc, byte| acc.wrapping_add(u16::from(*byte)));
    let mut m: heapless::Vec<u8, 64> = heapless::Vec::new();
    m.push(7).unwrap();
    m.extend_from_slice(&SESSION_KEY).unwrap();
    m.extend_from_slice(&checksum.to_be_bytes()).unwrap();
    m.resize(24, 0x05).unwrap();
    let wrapped = ecdh::aes_key_wrap(&kek, &m).unwrap();

    let mut import: heapless::Vec<u8, 64> = heapless::Vec::new();
    import.push(wrapped.len() as u8).unwrap();
    import.extend_from_slice(&wrapped).unwrap();
    import.push(ecdh::HASH_SHA256).unwrap();
    import.push(ecdh::KEK_AES128).unwrap();
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
        )
        .1,
        Sw::OK
    );
    let material = applet.ecdh_material().expect("the material is provisioned");
    assert_eq!(material.wrapped.as_slice(), &wrapped);
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x82, b"123456")
        )
        .1,
        Sw::OK
    );
    (applet, rng, point)
}

/// An RSA-2048 decryption slot with PW1 in mode 82 verified.
fn rsa_decipher_applet() -> (OpenPgp<MemoryOpenPgpStore>, TestRng) {
    let mut applet = applet();
    let mut rng = TestRng(30);
    verify_pw3(&mut applet, &mut rng);
    assert_eq!(
        put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_RSA2048),
        Sw::OK
    );
    let _ = generate(&mut applet, &mut rng, 0xB8);
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x82, b"123456")
        )
        .1,
        Sw::OK
    );
    (applet, rng)
}

/// An X25519 decryption slot with PW1 in mode 82 verified.
fn x25519_decipher_applet() -> (OpenPgp<MemoryOpenPgpStore>, TestRng) {
    let mut applet = applet();
    let mut rng = TestRng(31);
    verify_pw3(&mut applet, &mut rng);
    assert_eq!(put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_X25519), Sw::OK);
    let _ = generate(&mut applet, &mut rng, 0xB8);
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x82, b"123456")
        )
        .1,
        Sw::OK
    );
    (applet, rng)
}

/// An OpenPGP CFB stream over the whole plaintext, built with a capacity
/// beyond what the card layer accepts, so tests can craft ciphertext the
/// card can only refuse by size. Sender side of `pgp_sym::encrypt_aes`.
fn encrypt_beyond_card_capacity(session_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};

    const BS: usize = 16;
    let encrypt_block = |key: &[u8], block: &[u8; BS]| -> [u8; BS] {
        let mut buf = aes::Block::from(*block);
        let cipher = aes::Aes128::new_from_slice(key).expect("a 16-byte session key");
        cipher.encrypt_block(&mut buf);
        buf.as_mut_slice().try_into().expect("16 octets")
    };
    let mut out = Vec::new();
    let mut fr = [0u8; BS];
    for block in plaintext.chunks(BS) {
        let fre = encrypt_block(session_key, &fr);
        let start = out.len();
        for (index, byte) in block.iter().enumerate() {
            out.push(byte ^ fre[index]);
        }
        fr = [0u8; BS];
        fr[..block.len()].copy_from_slice(&out[start..]);
    }
    out
}

/// The streamed body of an OpenPGP message around `data`: the random prefix
/// with the repeated quick-check octets, the data and the modification
/// detection code — the exact input the card deciphers.
pub(crate) fn streamed_body(session_key: &[u8], data: &[u8]) -> Vec<u8> {
    use sha1::Digest as _;

    let mut prefix = [0x11u8; 16];
    prefix[14] = prefix[12];
    prefix[15] = prefix[13];
    let mut plaintext = Vec::new();
    plaintext.extend_from_slice(&prefix);
    plaintext.extend_from_slice(&[prefix[14], prefix[15]]);
    plaintext.extend_from_slice(data);
    plaintext.extend_from_slice(&[0xD3, 0x14]);
    let mut digest = sha1::Sha1::new();
    digest.update(&plaintext);
    plaintext.extend_from_slice(&digest.finalize());
    if plaintext.len() <= pgp_sym::MAX_DATA {
        pgp_sym::encrypt_aes(session_key, &plaintext)
            .unwrap()
            .to_vec()
    } else {
        encrypt_beyond_card_capacity(session_key, &plaintext)
    }
}

/// The closed round-trip contract: an accepted `PUT DATA D2` persists the
/// decryption slot with `len = 104` (32 bytes of scalar plus the 72 bytes of
/// RFC 6637 material) and `decode_state` understands exactly that width — on
/// the decryption slot, under the algorithms the import is handled under — so
/// a fresh session, what a boot of a provisioned card sees, recovers the
/// slot the card itself just wrote, including its PINs and counters. The
/// state an accepted command writes survives the session; unknown widths
/// still fail closed (the `state_roundtrip` module pins the domain).
///
/// This used to pin the production bug `decode_state` had (any non-RSA slot
/// wider than 48 octets refused, so a boot re-initialized the card) before
/// the S9 repair; the assertion was inverted when the decoder learned the
/// ECDH geometry.
#[test]
fn d2_provisioned_state_survives_across_sessions() {
    let mut rng = TestRng(99);
    let mut store = MemoryOpenPgpStore::new();
    let wrapped = [0x44u8; 32];
    {
        let mut applet = OpenPgp::new(store);
        assert_eq!(applet.select().sw, Sw::OK);
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_VERIFY, 0, 0x83, b"12345678")
            )
            .1,
            Sw::OK
        );
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_GENERATE, 0x80, 0, &[0xB8, 0x00])
            )
            .1,
            Sw::OK
        );
        let mut import: heapless::Vec<u8, 64> = heapless::Vec::new();
        import.push(wrapped.len() as u8).unwrap();
        import.extend_from_slice(&wrapped).unwrap();
        import.push(ecdh::HASH_SHA256).unwrap();
        import.push(ecdh::KEK_AES128).unwrap();
        assert_eq!(
            run(
                &mut applet,
                &mut rng,
                &frame(INS_PUT_DATA, 0x00, 0xD2, &import)
            )
            .1,
            Sw::OK
        );
        assert!(applet.ecdh_material().is_some());
        store = core::mem::take(applet.store_mut());
    }
    // Fresh session: the same store, brand-new RAM (a boot).
    let mut rebooted = OpenPgp::new(store);
    assert_eq!(rebooted.select().sw, Sw::OK);
    assert!(
        rebooted.ecdh_material().is_some(),
        "the fresh session must recover the provisioned slot"
    );
    assert_eq!(
        rebooted
            .ecdh_material()
            .expect("provisioned")
            .wrapped
            .as_slice(),
        &wrapped
    );
    assert_eq!(rebooted.keys[1].len, ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES);
}

/// AC-1: every malformed frame on the decipher path answers one closed,
/// empty status word on all three slot kinds, with the state intact. The
/// anti-leak check of AC-6 lives on every refusal right here.
///
/// The RSA inputs document the card-spec fallback semantics: a truncated TLV
/// degrades to the raw input, and only `rsa_cipher_block` refuses a short
/// block — a raw 256-byte block stays legitimate by design.
#[test]
fn decipher_refuses_truncated_and_nested_tlv_frames() {
    // RSA path: the malformed frames degrade to unwrappable shapes and the
    // block normalization refuses them.
    let (mut applet, mut rng) = rsa_decipher_applet();
    for input in STRUCTURAL_REFUSALS {
        let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, input));
        assert_eq!(sw, Sw::WRONG_DATA, "RSA refuses {input:?}");
        assert!(data.is_empty(), "RSA refuses with an empty body");
        assert_never_leaks(&data, &applet, None);
    }
    assert!(
        applet.keys[1].present,
        "the refused decipher changed nothing"
    );

    // ECDH P-256 with RFC 6637 material: the point furniture is validated
    // before any card-side math.
    let (mut applet, mut rng, _) = ecdh_p256_applet(32);
    let ephemeral_point = fixture_ephemeral_point();
    let anchored = applet.ecdh_material().expect("the material is provisioned");
    for input in STRUCTURAL_REFUSALS {
        let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, input));
        assert_eq!(sw, Sw::WRONG_DATA, "ECDH refuses {input:?}");
        assert!(data.is_empty());
        assert_eq!(
            applet.ecdh_material().as_ref(),
            Some(&anchored),
            "the refused decipher kept the slot"
        );
        assert_never_leaks(&data, &applet, None);
    }
    for point in [&ZERO_POINT[..], &INFINITY_POINT[..], &OFF_CURVE_POINT[..]] {
        let command = point_command(point, Some(&FOREIGN_CIPHER));
        let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
        assert_eq!(sw, Sw::WRONG_DATA, "the card refuses the point {point:?}",);
        assert!(
            data.is_empty(),
            "the off-curve point never leaks the shared secret"
        );
        assert_never_leaks(&data, &applet, None);
    }
    // The `80` DO of the encrypted data is mandatory on the RFC 6637 path.
    let command = point_command(&ephemeral_point, None);
    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(
        sw,
        Sw::WRONG_DATA,
        "the card refuses a decipher without the cipher DO"
    );
    assert!(data.is_empty());
    assert_eq!(applet.ecdh_material().as_ref(), Some(&anchored));
    assert_never_leaks(&data, &applet, None);

    // X25519: the same structural furniture (any 32 bytes would be a valid
    // point, so only the shapes refuse here).
    let (mut applet, mut rng) = x25519_decipher_applet();
    for input in STRUCTURAL_REFUSALS {
        let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, input));
        assert_eq!(sw, Sw::WRONG_DATA, "X25519 refuses {input:?}");
        assert!(data.is_empty());
        assert_never_leaks(&data, &applet, None);
    }
    assert!(applet.keys[1].present);
}

/// AC-2: the four accepted `wrapped_len` frontiers of the key wrap domain
/// (24/32/40/48) with every KEK id and with and without the optional sender
/// fingerprint import byte for byte round-trip.
#[test]
fn d2_accepts_the_wrapped_len_frontiers_24_32_40_48() {
    let mut applet = applet();
    let mut rng = TestRng(55);
    verify_pw3(&mut applet, &mut rng);
    let _ = generate(&mut applet, &mut rng, 0xB8);
    assert!(applet.ecdh_material().is_none(), "nothing provisioned yet");

    for wrapped_len in [24usize, 32, 40, 48] {
        for kek in [7u8, 8, 9] {
            for with_fingerprint in [false, true] {
                let mut import: heapless::Vec<u8, 128> = heapless::Vec::new();
                import.push(wrapped_len as u8).unwrap();
                import.resize(1 + wrapped_len, 0x66).unwrap();
                import.push(ecdh::HASH_SHA256).unwrap();
                import.push(kek).unwrap();
                let expected_fingerprint = if with_fingerprint {
                    import.extend_from_slice(&[0x77u8; 20]).unwrap();
                    Some([0x77u8; 20])
                } else {
                    None
                };
                let (data, sw) = run(
                    &mut applet,
                    &mut rng,
                    &frame(INS_PUT_DATA, 0x00, 0xD2, &import),
                );
                assert_eq!(
                    sw,
                    Sw::OK,
                    "the wrapped_len {wrapped_len} frontier is in the key wrap domain"
                );
                assert!(data.is_empty());
                let material = applet.ecdh_material().expect("the import is provisioned");
                assert_eq!(
                    material.wrapped.as_slice(),
                    &import[1..1 + wrapped_len],
                    "the wrapped key round-trips"
                );
                assert_eq!(material.kdf_hash, ecdh::HASH_SHA256);
                assert_eq!(material.kek_alg, kek, "the KEK id round-trips");
                assert_eq!(
                    material.fingerprint, expected_fingerprint,
                    "the optional fingerprint round-trips"
                );
            }
        }
    }
}

/// AC-3: bodies below the parseable minimum (empty, three bytes, four bytes)
/// and totals off the declared base are refused with a single status word —
/// zero saves and a slot that keeps the anchored material. The full
/// `wrapped_len` domain (0/8/16/25/49) stays guarded by
/// `d2_rejects_wrapped_len_outside_the_key_wrap_domain`; only its frontier
/// is re-asserted here.
#[test]
fn d2_refuses_short_bodies_and_keeps_the_slot() {
    let mut rng = TestRng(60);
    let mut applet = OpenPgp::new(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()));
    assert_eq!(applet.select().sw, Sw::OK);
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x83, b"12345678")
        )
        .1,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_GENERATE, 0x80, 0, &[0xB8, 0x00])
        )
        .1,
        Sw::OK
    );

    let wrapped = [0x44u8; 24];
    let mut anchored_import: heapless::Vec<u8, 64> = heapless::Vec::new();
    anchored_import.push(wrapped.len() as u8).unwrap();
    anchored_import.extend_from_slice(&wrapped).unwrap();
    anchored_import.push(ecdh::HASH_SHA256).unwrap();
    anchored_import.push(ecdh::KEK_AES128).unwrap();
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_PUT_DATA, 0x00, 0xD2, &anchored_import)
        )
        .1,
        Sw::OK
    );
    let anchored = applet.ecdh_material().expect("the material is anchored");
    let saved = applet.store.save_calls;

    // The parseable body needs at least the length octet, the two KDF octets
    // and the declared wrap block: every shorter or off-base total refuses
    // before anything is materialized.
    let mut off_short: Vec<u8> = vec![0x18];
    off_short.resize(26, 0x55);
    let mut off_long: Vec<u8> = vec![0x18];
    off_long.resize(48, 0x55);
    let refusals: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x18, 0x01, 0x02],
        vec![0x20, 0x01, 0x02, 0x03],
        off_short,
        off_long,
        vec![0x00, 0x08, 0x08, 0x07],
        vec![0x31, 0x08, 0x08, 0x07, 0x55],
    ];
    for body in &refusals {
        let (data, sw) = run(
            &mut applet,
            &mut rng,
            &frame(INS_PUT_DATA, 0x00, 0xD2, body),
        );
        assert_eq!(sw, Sw::WRONG_DATA, "the D2 body {body:?} is out of domain");
        assert!(data.is_empty());
        assert_eq!(applet.ecdh_material().as_ref(), Some(&anchored));
        assert_never_leaks(&data, &applet, None);
        assert_eq!(applet.store.save_calls, saved, "no save on a refusal");
    }

    // The refusals themselves never staged anything in the store: the
    // zero saves across the loop are the load-side guarantee, and the slot
    // kept the anchored material the whole time. (Reload and reboot
    // behavior over a provisioned slot lives in
    // `d2_provisioned_state_survives_across_sessions` and in the
    // `state_roundtrip` module, not here.)
}

/// AC-4: a decryption slot whose RFC 6637 material sits below or off the
/// `EcdhMaterial::from_slot` frontier (length 104, internal wrapped length
/// 0/49) makes the card fall back to the partial decrypt of the card spec —
/// a deterministic `9000` plus the 32-byte shared secret, PW1 in mode 82
/// verified first — and the exact frontier reads the material again.
#[test]
fn decipher_falls_back_deterministically_when_the_slot_material_is_incomplete() {
    use p256::elliptic_curve::sec1::ToSec1Point as _;

    let (mut applet, mut rng, card_point) = ecdh_p256_applet(40);
    let anchored = applet.ecdh_material().expect("the material is provisioned");
    let total = ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES;
    assert_eq!(
        applet.keys[1].len, total,
        "the provisioned slot is at the frontier"
    );
    let ephemeral = p256::SecretKey::from_slice(&EPHEMERAL_SCALAR).unwrap();
    let ephemeral_point = ephemeral.public_key().to_sec1_point(false);
    let card_public = p256::PublicKey::from_sec1_bytes(&card_point).unwrap();
    let z = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine())
        .raw_secret_bytes()
        .as_slice()
        .to_vec();

    // A valid point with a cipher the material cannot decrypt: in the RFC
    // 6637 mode the answer is one closed status word, in the fallback the
    // cipher is ignored and the shared secret is released.
    let command = point_command(ephemeral_point.as_bytes(), Some(&FOREIGN_CIPHER));

    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(sw, Sw::NO_PRECISE_DIAGNOSIS, "the wrap cannot be decrypted");
    assert!(data.is_empty());

    // The release of the shared secret is PW1 in mode 82 business first.
    let mut gate = super::applet();
    let mut gate_rng = TestRng(41);
    verify_pw3(&mut gate, &mut gate_rng);
    let _ = generate(&mut gate, &mut gate_rng, 0xB8);
    let (data, sw) = run(
        &mut gate,
        &mut gate_rng,
        &frame(INS_PSO, 0x80, 0x86, &command),
    );
    assert_eq!(
        sw,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "gated before mode 82"
    );
    assert!(data.is_empty());
    assert_never_leaks(&data, &gate, None);

    // Length 103: under the material floor, the card falls back while the
    // private scalar is untouched, so the released secret is the documented Z.
    applet.keys[1].len = total - 1;
    assert!(
        applet.ecdh_material().is_none(),
        "the frontier reads invalid"
    );
    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(sw, Sw::OK);
    assert_eq!(data.as_slice(), z.as_slice());
    assert_never_leaks(&data, &applet, Some(&z));

    // A defective point frame refuses inside the fallback the same way.
    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, EMPTY_86));
    assert_eq!(sw, Sw::WRONG_DATA, "an invalid point still refuses");
    assert!(data.is_empty());
    assert_never_leaks(&data, &applet, None);

    // Length 32: the bare scalar of a freshly generated slot.
    applet.keys[1].len = ECDH_KEY_BYTES;
    assert!(applet.ecdh_material().is_none());
    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(sw, Sw::OK);
    assert_eq!(data.as_slice(), z.as_slice());
    assert_never_leaks(&data, &applet, Some(&z));

    // Length 104 with a zero or oversized internal wrapped length sits
    // directly under the accepted `from_slot` frontier.
    applet.keys[1].len = total;
    for wrapped_len in [0u8, 49] {
        applet.keys[1].material[ECDH_KEY_BYTES] = wrapped_len;
        assert!(
            applet.ecdh_material().is_none(),
            "wrapped_len {wrapped_len}"
        );
        let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
        assert_eq!(sw, Sw::OK);
        assert_eq!(data.as_slice(), z.as_slice());
        assert_never_leaks(&data, &applet, Some(&z));
    }

    // The exact frontier 104 reads the valid material again and the card is
    // back in the RFC 6637 mode.
    applet.keys[1].material[ECDH_KEY_BYTES] = anchored.wrapped.len() as u8;
    assert_eq!(applet.keys[1].len, total);
    assert_eq!(applet.ecdh_material().as_ref(), Some(&anchored));
    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(
        sw,
        Sw::NO_PRECISE_DIAGNOSIS,
        "the RFC 6637 mode is restored"
    );
    assert!(data.is_empty());
    assert_never_leaks(&data, &applet, None);
}

/// AC-5: a body beyond `MAX_DATA` rides an extended APDU and the answer is a
/// single closed status word — no panic and no state change.
#[test]
fn oversized_ciphertext_answers_one_status_word_without_panicking() {
    let (mut applet, mut rng, _) = ecdh_p256_applet(42);
    let anchored = applet.ecdh_material().expect("the material is provisioned");

    let data = vec![0x44u8; 4300];
    let session_key = session_key(&mut rng);
    let ciphertext = streamed_body(&session_key, &data);
    assert!(
        ciphertext.len() > pgp_sym::MAX_DATA,
        "the crafted body exceeds the decryptable size"
    );
    let mut command = tlv(0x86, &fixture_ephemeral_point());
    command.extend_from_slice(&tlv(0x80, &ciphertext));
    let (data, sw) = run(
        &mut applet,
        &mut rng,
        &extended_frame(INS_PSO, 0x80, 0x86, &command),
    );
    assert_eq!(
        sw,
        Sw::NO_PRECISE_DIAGNOSIS,
        "one status word for a > 4096 body"
    );
    assert!(
        data.is_empty(),
        "no plaintext fragment escapes the size refusal"
    );
    assert_eq!(
        applet.ecdh_material().as_ref(),
        Some(&anchored),
        "no state change"
    );
    assert_never_leaks(&data, &applet, None);
}

/// AC-7: an all-zero X25519 point is curve behavior, not an error — the
/// answer is deterministic (`9000` plus 32 zero bytes), the release stays
/// gated by PW1 in mode 82, and refusing non-contributory points is a
/// deliberate non-goal of the suite.
#[test]
fn x25519_zero_point_is_curve_behavior_not_an_error() {
    let zero = [0x00u8; 32];
    let command = point_command(&zero, None);
    let mut applet = applet();
    let mut rng = TestRng(70);
    verify_pw3(&mut applet, &mut rng);
    assert_eq!(put_attrs(&mut applet, &mut rng, 0xC2, ATTRS_X25519), Sw::OK);
    let _ = generate(&mut applet, &mut rng, 0xB8);

    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(
        sw,
        Sw::SECURITY_STATUS_NOT_SATISFIED,
        "gated before mode 82"
    );
    assert!(data.is_empty());
    assert_never_leaks(&data, &applet, None);

    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x82, b"123456")
        )
        .1,
        Sw::OK
    );
    let (data, sw) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(sw, Sw::OK);
    assert_eq!(data.len(), 32);
    assert_eq!(
        data.as_slice(),
        zero,
        "the zero point agrees to the zero secret"
    );
    let (again, _) = run(&mut applet, &mut rng, &frame(INS_PSO, 0x80, 0x86, &command));
    assert_eq!(
        again.as_slice(),
        data.as_slice(),
        "the answer is deterministic"
    );
}

/// AC-1..AC-3 of `specs/openpgp-decipher-response-window.md`; AC-4 is the
/// intactness of the sibling suites this module belongs to, verified by the
/// gates. This is the INFO limitation the S8 suite recorded, re-anchored as
/// the executable contract after decision (C): the 2048-octet response
/// window of the full-RFC 6637 decipher is kept, not widened. Exactly 2047
/// and 2048 octets ride the window byte for byte; 2049 refuses `6A84` with
/// an empty body — zero bytes beyond the window, the private material stays
/// on its documented route, and the refusal leaves the session (slot
/// material, store saves, PW1 mode 82 flag) pristine, with a small decipher
/// on the same slot immediately after. The real transport ceiling, measured
/// over the CCID pipeline, lives in `response_window` (AC-5).
#[test]
fn decipher_response_window_boundary_is_the_frozen_contract() {
    let (mut applet, mut rng, _) =
        ecdh_p256_applet_over(FlakyOpenPgpStore::new(MemoryOpenPgpStore::new()), 43);
    let ephemeral_point = fixture_ephemeral_point();
    let anchored = applet.ecdh_material().expect("the material is provisioned");
    let saved = applet.store.save_calls;
    assert!(
        applet.pw1_other_verified,
        "PW1 in mode 82 is verified at the start"
    );

    for (data_len, expected_sw) in [
        (2047usize, Sw::OK),
        (2048usize, Sw::OK),
        (2049usize, Sw::NOT_ENOUGH_MEMORY),
        (2100usize, Sw::NOT_ENOUGH_MEMORY),
    ] {
        let data = vec![0x44u8; data_len];
        let ciphertext = streamed_body(&SESSION_KEY, &data);
        assert!(
            ciphertext.len() <= pgp_sym::MAX_DATA,
            "the size refusal beyond the stream limit is the separate closed contract"
        );
        let command = point_command(&ephemeral_point, Some(&ciphertext));
        let (plain, sw) = run(
            &mut applet,
            &mut rng,
            &extended_frame(INS_PSO, 0x80, 0x86, &command),
        );
        assert_eq!(sw, expected_sw, "the {data_len}-octet window boundary");
        if sw == Sw::OK {
            assert_eq!(
                plain.len(),
                data_len,
                "the window returns the whole message"
            );
            assert_eq!(plain.as_slice(), &data[..], "byte-exact inside the window");
        } else {
            assert!(
                plain.is_empty(),
                "`6A84` with an empty body: zero bytes beyond the window"
            );
            assert_eq!(
                applet.ecdh_material().as_ref(),
                Some(&anchored),
                "the refusal kept the slot (AC-3)"
            );
            assert_eq!(
                applet.store.save_calls, saved,
                "no save on a window refusal (AC-3)"
            );
            assert!(
                applet.pw1_other_verified,
                "the refusal left the PW1 mode 82 flag intact (AC-3)"
            );
            // A small decipher on the same slot rounds the boundary refusal.
            let small = vec![0x11u8; 256];
            let ciphertext = streamed_body(&SESSION_KEY, &small);
            let command = point_command(&ephemeral_point, Some(&ciphertext));
            let (plain, sw) = run(
                &mut applet,
                &mut rng,
                &extended_frame(INS_PSO, 0x80, 0x86, &command),
            );
            assert_eq!(sw, Sw::OK, "the session survives a window refusal (AC-3)");
            assert_eq!(
                plain.as_slice(),
                small.as_slice(),
                "byte-exact decipher right after the refusal (AC-3)"
            );
        }
        assert_eq!(applet.ecdh_material().as_ref(), Some(&anchored));
        assert_never_leaks(&plain, &applet, None);
    }
    assert_eq!(
        applet.store.save_calls, saved,
        "the whole boundary tour saves nothing (AC-3)"
    );
}
