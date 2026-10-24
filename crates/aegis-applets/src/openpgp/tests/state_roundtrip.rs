//! Session round-trip of the OpenPGP state (`specs/openpgp-d2-state-roundtrip.md`):
//! the state an accepted command writes — keys, PINs, counters and the DOs —
//! survives a cold boot and an in-session re-select byte-identically, the
//! decoder fail-closes on every width outside the writer's geometry and the
//! blob written before the repair keeps decoding with no version bump.

use super::adversarial_apdu::{
    SESSION_KEY, ecdh_p256_applet, fixture_ephemeral_point, point_command, streamed_body,
};
use super::*;
use std::vec::Vec;

/// One fully provisioned session: ECDH P-256 decryption key with RFC 6637
/// material (the adversary-suite fixture), the DOs set, a signature key with
/// one counter tick, a custom PW1 provisioned through PW3 and one consumed
/// retry attempt, all persisted.
fn provisioned_applet(seed: u64) -> (OpenPgp<MemoryOpenPgpStore>, TestRng) {
    let (mut applet, mut rng, _point) = ecdh_p256_applet(seed);
    for (tag, (p1, p2)) in [
        (b"Tile Co.".as_slice(), (0u8, 0x5B)),
        (b"pt".as_slice(), (0x5F, 0x2D)),
        (b"9".as_slice(), (0x5F, 0x35)),
        (b"https://tile.example".as_slice(), (0x5F, 0x50)),
        (b"-----X-509-----".as_slice(), (0x7F, 0x21)),
    ] {
        assert_eq!(
            run(&mut applet, &mut rng, &frame(INS_PUT_DATA, p1, p2, tag)).1,
            Sw::OK
        );
    }
    let _ = generate(&mut applet, &mut rng, 0xB6);
    // The custom PW1 arrives through the PW3-gated unblock and one consumed
    // attempt anchors a nonzero retry counter in the sealed state.
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_RESET_RETRY_COUNTER, 0x02, 0x81, b"44556677")
        )
        .1,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x81, b"000000")
        )
        .1,
        Sw::retries_left(2)
    );
    // One signature ticks the persisted counter.
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x81, b"44556677")
        )
        .1,
        Sw::OK
    );
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_PSO, 0x9E, 0x9A, &[0xA5u8; 32])
        )
        .1,
        Sw::OK
    );
    (applet, rng)
}

/// `GET DATA` with the status word asserted: the DO identity of a session.
fn read_do<S: OpenPgpStore>(
    applet: &mut OpenPgp<S>,
    rng: &mut TestRng,
    p1: u8,
    p2: u8,
) -> heapless::Vec<u8, 2048> {
    let (data, sw) = run(applet, rng, &frame(INS_GET_DATA, p1, p2, &[]));
    assert_eq!(sw, Sw::OK);
    data
}

/// The slot slab of an accepted `PUT DATA D2` import, exactly the geometry
/// `EcdhMaterial::store` writes: the scalar, the wrapped length, the wrapped
/// key left-aligned, the KDF hash id, the KEK id, the fingerprint flag and the
/// fingerprint octets.
fn ecdh_slab(wrapped_len: usize) -> [u8; SLOT_MATERIAL_BYTES] {
    let mut slab = [0u8; SLOT_MATERIAL_BYTES];
    let material = &mut slab[ECDH_KEY_BYTES..ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES];
    material[0] = wrapped_len as u8;
    material[1..1 + wrapped_len].fill(0x44);
    material[1 + ECDH_WRAPPED_MAX] = ecdh::HASH_SHA256;
    material[2 + ECDH_WRAPPED_MAX] = ecdh::KEK_AES128;
    material[3 + ECDH_WRAPPED_MAX] = 1;
    material[4 + ECDH_WRAPPED_MAX..].copy_from_slice(&[0xE2; 20]);
    slab
}

/// A v3 blob hand-built in the layout of `save_state` (the pattern of
/// `state_v1_migrates_to_p256_defaults`): version, two PIN slots,
/// `[present, len u16, algo, slab]` per key, empty DOs, zero counter. Every
/// key slot carries `slab` as its raw octets; the length under test selects
/// the slice.
fn hand_built_v3(slots: &[(u8, usize, u8); 3], slab: &[u8; SLOT_MATERIAL_BYTES]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.push(STATE_VERSION);
    let mut pin = PinSlot::new(PW_POLICY);
    pin.set(b"123456").unwrap();
    let mut encoded = [0u8; crate::pin::PIN_STATE_LEN];
    pin.encode(&mut encoded).unwrap();
    bytes.extend_from_slice(&encoded);
    bytes.extend_from_slice(&encoded);
    for (index, (present, len, algo)) in slots.iter().enumerate() {
        bytes.push(*present);
        bytes.extend_from_slice(&(*len as u16).to_be_bytes());
        bytes.push(*algo);
        bytes.extend_from_slice(&slabs_copy(slab)[index]);
    }
    bytes.push(0);
    bytes.extend_from_slice(&[0u8; MAX_NAME]);
    bytes.push(0);
    bytes.extend_from_slice(&[0u8; 8]);
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&[0u8; MAX_URL]);
    for _ in 0..3 {
        bytes.extend_from_slice(&0u16.to_be_bytes());
        bytes.extend_from_slice(&[0u8; MAX_CERTIFICATE]);
    }
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes
}

fn slabs_copy(slab: &[u8; SLOT_MATERIAL_BYTES]) -> [[u8; SLOT_MATERIAL_BYTES]; 3] {
    [*slab, *slab, *slab]
}

/// A cold boot over a store holding only `blob`: the refused decode falls
/// onto the documented re-initialization defaults.
fn cold_boot_uses_defaults(bytes: &[u8]) {
    let mut store = MemoryOpenPgpStore::new();
    assert!(store.save(bytes));
    let mut applet = OpenPgp::new(store);
    assert_eq!(applet.select().sw, Sw::OK);
    assert!(
        applet.keys.iter().all(|key| !key.present),
        "the refused decode never carries keys"
    );
    let mut rng = TestRng(29);
    assert_eq!(
        run(
            &mut applet,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x83, b"12345678")
        )
        .1,
        Sw::OK,
        "the failed decode re-initializes the PINs to the defaults"
    );
}

/// AC-1/AC-2: provision the card (PW3, keys, `PUT DATA D2`, DOs, custom PIN,
/// counters) and boot a fresh instance over the same store: the material, the
/// fingerprints DO and the whole data-object identity survive byte-identical.
#[test]
fn d2_provisioned_state_round_trips_to_a_cold_session() {
    const DO_TAGS: [(u8, u8); 6] = [
        (0x00, 0x5B),
        (0x5F, 0x2D),
        (0x5F, 0x35),
        (0x5F, 0x50),
        (0x7F, 0x21),
        (0x00, 0x7A),
    ];
    let store;
    let material;
    let mut scalar = [0u8; 32];
    let fingerprints;
    let mut identity = Vec::new();
    {
        let (mut applet, mut rng) = provisioned_applet(7);
        material = applet.ecdh_material().expect("the D2 slot is provisioned");
        scalar.copy_from_slice(&applet.keys[1].material[..32]);
        fingerprints = read_do(&mut applet, &mut rng, 0x00, 0xC5);
        for (p1, p2) in DO_TAGS {
            identity.push(read_do(&mut applet, &mut rng, p1, p2));
        }
        store = core::mem::take(applet.store_mut());
    }
    let mut rebooted = OpenPgp::new(store);
    assert_eq!(rebooted.select().sw, Sw::OK);
    assert_eq!(
        rebooted.keys[1].len,
        ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES,
        "the state decodes with the exact D2 geometry the writer produces"
    );
    assert_eq!(rebooted.ecdh_material().as_ref(), Some(&material));
    assert_eq!(rebooted.keys[1].material[..32], scalar);
    let mut rng = TestRng(8);
    assert_eq!(
        read_do(&mut rebooted, &mut rng, 0x00, 0xC5),
        fingerprints,
        "the fingerprints DO is identical"
    );
    for (index, &(p1, p2)) in DO_TAGS.iter().enumerate() {
        assert_eq!(
            read_do(&mut rebooted, &mut rng, p1, p2),
            identity[index],
            "the DO {:?} survives the reboot",
            (p1, p2)
        );
    }
}

/// AC-3: after the reboot, `VERIFY` with the persisted custom PIN opens the
/// RFC 6637 decipher and the exact plaintext comes back; the same cycle
/// repeats after an in-session re-select.
#[test]
fn decipher_after_reboot_returns_the_plaintext_with_the_persisted_pin() {
    let plaintext: Vec<u8> = (0..128).map(|i| (i as u8).wrapping_mul(13) | 1).collect();
    let store;
    let ciphertext;
    {
        let (mut applet, _) = provisioned_applet(9);
        ciphertext = streamed_body(&SESSION_KEY, &plaintext);
        store = core::mem::take(applet.store_mut());
    }
    let mut rng = TestRng(10);
    let mut rebooted = OpenPgp::new(store);
    assert_eq!(rebooted.select().sw, Sw::OK);
    assert_eq!(
        run(
            &mut rebooted,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x82, b"44556677")
        )
        .1,
        Sw::OK
    );
    let command = point_command(fixture_ephemeral_point().as_slice(), Some(&ciphertext));
    let (plain, sw) = run(
        &mut rebooted,
        &mut rng,
        &frame(INS_PSO, 0x80, 0x86, &command),
    );
    assert_eq!(sw, Sw::OK);
    assert_eq!(
        plain.as_slice(),
        plaintext.as_slice(),
        "the RFC 6637 decipher round-trips after the boot"
    );
    // The same cycle survives a re-select in the same instance.
    assert_eq!(rebooted.select().sw, Sw::OK);
    assert_eq!(
        run(
            &mut rebooted,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x82, b"44556677")
        )
        .1,
        Sw::OK
    );
    let (plain_again, sw_again) = run(
        &mut rebooted,
        &mut rng,
        &frame(INS_PSO, 0x80, 0x86, &command),
    );
    assert_eq!(sw_again, Sw::OK);
    assert_eq!(plain_again.as_slice(), plaintext.as_slice());
}

/// AC-4: the provisioned custom PIN, its persisted retry counter and the
/// material all verify in the new session and keep verifying after a
/// re-select: the reload no longer overwrites the state with the defaults.
#[test]
fn custom_pin_and_persisted_counter_survive_cold_boot_and_re_select() {
    let store;
    {
        let (mut applet, _) = provisioned_applet(11);
        store = core::mem::take(applet.store_mut());
    }
    let mut rng = TestRng(12);
    let mut rebooted = OpenPgp::new(store);
    assert_eq!(rebooted.select().sw, Sw::OK);
    // The counter loaded from the store is exactly the persisted one.
    assert_eq!(
        run(&mut rebooted, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
        Sw::retries_left(2)
    );
    // The custom PIN verifies; the default does not (and stays gone).
    assert_eq!(
        run(
            &mut rebooted,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x81, b"123456")
        )
        .1,
        Sw::retries_left(1)
    );
    assert_eq!(
        run(
            &mut rebooted,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x81, b"44556677")
        )
        .1,
        Sw::OK
    );
    // A re-select reloads the same store: one more failure, then the
    // provisioned PIN again — no default replacement, no counter reset.
    assert_eq!(rebooted.select().sw, Sw::OK);
    assert_eq!(
        run(&mut rebooted, &mut rng, &frame(INS_VERIFY, 0, 0x81, &[])).1,
        Sw::retries_left(1)
    );
    assert_eq!(
        run(
            &mut rebooted,
            &mut rng,
            &frame(INS_VERIFY, 0, 0x81, b"44556677")
        )
        .1,
        Sw::OK,
        "the re-select keeps the provisioned PIN"
    );
    assert!(
        rebooted.ecdh_material().is_some(),
        "the re-select keeps the provisioned material"
    );
}

/// AC-5: the 104-octet width fails closed everywhere but the exact domain the
/// writer produces. The slab under test is internally well-formed throughout:
/// the refusals answer only to the length, the slot or the algorithm.
#[test]
fn unknown_widths_and_slots_still_fail_closed() {
    let slab = ecdh_slab(32);
    for (label, slots) in [
        (
            "len 105 in the decryption slot",
            [
                (0u8, 0usize, KEY_ALGO_UNSET),
                (1, 105, KEY_ALGO_ECDH_P256),
                (0, 0, KEY_ALGO_UNSET),
            ],
        ),
        (
            "len 103 in the decryption slot",
            [
                (0u8, 0usize, KEY_ALGO_UNSET),
                (1, 103, KEY_ALGO_ECDH_P256),
                (0, 0, KEY_ALGO_UNSET),
            ],
        ),
        (
            "len 104 in the signature slot",
            [
                (1u8, 104usize, KEY_ALGO_UNSET),
                (0, 0, KEY_ALGO_UNSET),
                (0, 0, KEY_ALGO_UNSET),
            ],
        ),
        (
            "len 104 in the authentication slot",
            [
                (0u8, 0usize, KEY_ALGO_UNSET),
                (0, 0, KEY_ALGO_UNSET),
                (1, 104, KEY_ALGO_UNSET),
            ],
        ),
        (
            "len 104 with X25519 registered",
            [
                (0u8, 0usize, KEY_ALGO_UNSET),
                (1, 104, KEY_ALGO_ECDH_X25519),
                (0, 0, KEY_ALGO_UNSET),
            ],
        ),
        (
            "len 104 with EdDSA registered",
            [
                (0u8, 0usize, KEY_ALGO_UNSET),
                (1, 104, KEY_ALGO_EDDSA),
                (0, 0, KEY_ALGO_UNSET),
            ],
        ),
        (
            "the RSA slab width with an ECDH algorithm",
            [
                (0u8, 0usize, KEY_ALGO_UNSET),
                (1, rsa::RSA_BLOB_BYTES, KEY_ALGO_ECDH_P256),
                (0, 0, KEY_ALGO_UNSET),
            ],
        ),
    ] {
        let bytes = hand_built_v3(&slots, &slab);
        let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
        assert!(!applet.decode_state(&bytes), "{label} must fail closed");
        cold_boot_uses_defaults(&bytes);
    }
}

/// AC-7: the blob the card wrote before the repair (slot `len = 104`,
/// algorithm UNSET) is byte-identical to what the repaired decoder accepts —
/// the version stays 3, nothing re-provisions and a re-save decodes again;
/// the `GENERATE` scalar width keeps being accepted beside the book-in.
#[test]
fn pre_repair_blob_decodes_book_in_and_resaves_without_a_version_bump() {
    let slab = ecdh_slab(32);
    let material_slots = [
        (0u8, 0usize, KEY_ALGO_UNSET),
        (1, ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES, KEY_ALGO_UNSET),
        (0, 0, KEY_ALGO_UNSET),
    ];
    let mut bytes = hand_built_v3(&material_slots, &slab);
    // The version the card wrote before the repair is a literal, not the
    // constant: a `STATE_VERSION` bump must fail this test instead of moving
    // the blob under test along with the decoder.
    bytes[0] = 3;
    let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
    assert!(
        applet.decode_state(&bytes),
        "the state written before the repair keeps decoding"
    );
    assert_eq!(applet.keys[1].len, ECDH_KEY_BYTES + ECDH_MATERIAL_BYTES);
    let material = applet
        .ecdh_material()
        .expect("the material of the blob loads");
    assert_eq!(material.wrapped.as_slice(), &[0x44; 32]);
    assert_eq!(material.kdf_hash, ecdh::HASH_SHA256);
    assert_eq!(material.kek_alg, ecdh::KEK_AES128);
    assert_eq!(material.fingerprint, Some([0xE2; 20]));
    // The recomposition stays on the same version: no migration, no bump.
    assert!(applet.save_state());
    assert_eq!(applet.state[0], 3, "no STATE_VERSION bump");
    let mut reopened = OpenPgp::new(MemoryOpenPgpStore::new());
    assert!(reopened.decode_state(&applet.state));
    assert_eq!(reopened.ecdh_material().as_ref(), Some(&material));
    // The GENERATE scalar width (len 32, algorithm UNSET) keeps decoding.
    let scalar_slots = [
        (0u8, 0usize, KEY_ALGO_UNSET),
        (1, 32usize, KEY_ALGO_UNSET),
        (0, 0, KEY_ALGO_UNSET),
    ];
    let scalar_bytes = hand_built_v3(&scalar_slots, &slab);
    let mut scalar_applet = OpenPgp::new(MemoryOpenPgpStore::new());
    assert!(
        scalar_applet.decode_state(&scalar_bytes),
        "the GENERATE scalar width keeps being accepted"
    );
    assert_eq!(scalar_applet.keys[1].len, 32);
}
