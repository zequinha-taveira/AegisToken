//! AC-5 of `specs/openpgp-decipher-response-window.md`: the transport ceiling
//! of the full-RFC 6637 decipher, measured over the real host pipeline —
//! CCID assembler → card front end → response-chaining router → OpenPGP
//! applet — with the `DefaultCard` shape the firmware instantiates (2048
//! response / 2100 message octets).
//!
//! Decision (C) keeps the 2048 / `6A84` applet window: over the transport
//! that window is unreachable, because the command input is gated first. The
//! largest scdaemon-shaped decipher command (`86‖80`, extended case `4E`)
//! that fits one CCID message answers `9000` byte for byte, and one octet of
//! frame more dies in the assembler with `CcidError::Overflow` — no status
//! word, no bytes, the applet never runs (the silent `card.reset()` the
//! firmware then applies on that error stays documented; this suite only
//! freezes the observable ceiling).

use std::cell::Cell;
use std::rc::Rc;
use std::vec::Vec;

use crate::aid;
use crate::card::{DefaultCard, Outcome};
use crate::ccid::{
    self, CcidError, MAX_MESSAGE_BYTES, PC_TO_RDR_ICC_POWER_ON, PC_TO_RDR_XFR_BLOCK,
    RDR_TO_PC_DATA_BLOCK,
};
use crate::router::Applet;

use super::adversarial_apdu::{
    EPHEMERAL_SCALAR, fixture_ephemeral_point, fixture_session_key, point_command, streamed_body,
};
use super::*;

/// A store that counts the saves the applet performs; the counter is
/// mirrored into an owned handle so the test can read it while the card
/// holds the applet.
struct CountedStore {
    inner: MemoryOpenPgpStore,
    saves: Rc<Cell<u32>>,
}

impl OpenPgpStore for CountedStore {
    fn load(&mut self, out: &mut [u8]) -> Option<usize> {
        self.inner.load(out)
    }

    fn save(&mut self, data: &[u8]) -> bool {
        self.saves.set(self.saves.get() + 1);
        self.inner.save(data)
    }

    fn clear(&mut self) -> bool {
        self.inner.clear()
    }
}

/// A CCID frame with the given message type, sequence and payload — the
/// 10-octet header shape `card.rs` builds in its own suite.
fn ccid_frame(message_type: u8, sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![message_type];
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0x00, sequence, 0x00, 0x00, 0x00]);
    out.extend_from_slice(payload);
    out
}

/// An `XfrBlock` frame carrying a command APDU.
fn xfr_frame(sequence: u8, apdu: &[u8]) -> Vec<u8> {
    ccid_frame(PC_TO_RDR_XFR_BLOCK, sequence, apdu)
}

/// Feed one CCID frame, process it and return the encoded CCID response.
fn poll_response(card: &mut DefaultCard<'_>, rng: &mut TestRng, frame: &[u8]) -> Vec<u8> {
    card.feed(frame).expect("the frame fits the assembler");
    let mut out = [0u8; MAX_MESSAGE_BYTES];
    let Some(Outcome::Response(len)) = card.poll(rng, &mut out).expect("the card polls") else {
        panic!("expected an encoded response");
    };
    out[..len].to_vec()
}

/// The APDU body and the status word of an encoded CCID data block.
fn apdu_response(encoded: &[u8]) -> (&[u8], [u8; 2]) {
    let body = &encoded[ccid::HEADER_LEN..];
    let sw = [body[body.len() - 2], body[body.len() - 1]];
    (&body[..body.len() - 2], sw)
}

/// The extended case-`4E` decipher APDU: extended `Lc`, the command data and
/// an extended `Le = 0`, so the router hands over everything it decrypted.
fn decipher_apdu(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut out = vec![0x00, INS_PSO, 0x80, 0x86, 0x00, (len >> 8) as u8, len as u8];
    out.extend_from_slice(data);
    out.extend_from_slice(&[0x00, 0x00]);
    out
}

/// The whole-frame length of the scdaemon-shaped decipher command carrying a
/// message of `message_len` octets: `HEADER_LEN` (CCID) + 9 (extended case
/// `4E`: 7 header octets plus the two `Le` octets) + the `86` TLV around the
/// 65-octet point (67) + the long-form `80` TLV (4, the stream of this size
/// always needs the `82` length form) + the streamed cipher (`message_len` +
/// the 40 octets of CFB furniture).
fn frame_len(message_len: usize) -> usize {
    ccid::HEADER_LEN + 9 + 67 + 4 + message_len + 40
}

/// AC-5: the real transport ceiling. Provision a full-RFC 6637 slot over the
/// card pipeline (SELECT → PW3 → `GENERATE` → `PUT DATA D2` → PW1 mode 82),
/// then measure the largest decipher the assembler opens: a `9000` byte
/// for byte, one octet of frame more → `CcidError::Overflow` with no status
/// word, no bytes, no save and an applet buffer untouched — the applet never
/// saw the command. The spec's §1.2 (~1974 octets) rounds the same ceiling
/// without the `Le` and long-form-length octets; per R2 the test asserts the
/// formula over the real assembled frame.
#[test]
fn transport_ceiling_of_the_full_decipher_is_the_ccid_input() {
    let saves = Rc::new(Cell::new(0u32));
    let mut applet = OpenPgp::new(CountedStore {
        inner: MemoryOpenPgpStore::new(),
        saves: Rc::clone(&saves),
    });
    let mut rng = TestRng(48);
    let mut applets: [&mut dyn Applet; 1] = [&mut applet];
    let mut card = DefaultCard::new(&mut applets);

    // --- Provisioning, over the card pipeline -------------------------------
    let _ = poll_response(
        &mut card,
        &mut rng,
        &ccid_frame(PC_TO_RDR_ICC_POWER_ON, 1, &[]),
    );
    assert!(card.is_powered());

    let mut select = vec![0x00, 0xA4, 0x04, 0x00, aid::OPENPGP.len() as u8];
    select.extend_from_slice(aid::OPENPGP);
    let response = poll_response(&mut card, &mut rng, &xfr_frame(2, &select));
    let (_, sw) = apdu_response(&response);
    assert_eq!(sw, [0x90, 0x00], "the OpenPGP applet is selected");
    assert_eq!(card.selected_aid(), Some(aid::OPENPGP));

    let response = poll_response(
        &mut card,
        &mut rng,
        &xfr_frame(3, &frame(INS_VERIFY, 0, 0x83, b"12345678")),
    );
    let (_, sw) = apdu_response(&response);
    assert_eq!(sw, [0x90, 0x00], "PW3 verifies the admin session");

    let response = poll_response(
        &mut card,
        &mut rng,
        &xfr_frame(4, &frame(INS_GENERATE, 0x80, 0, &[0xB8, 0x00])),
    );
    let (data, sw) = apdu_response(&response);
    assert_eq!(sw, [0x90, 0x00], "GENERATE produced the decryption slot");
    let card_point = tlv::find(
        tlv::find(data, 0x7F49).expect("a public key template"),
        0x86,
    )
    .expect("an EC point DO");
    assert_eq!(card_point.len(), 65, "the decryption key is a P-256 point");

    // The sender of a full-RFC 6637 message: an ephemeral point agreed with
    // the card's new key, the session key wrapped under the KEK the card
    // derives from that agreement, and a fixture fingerprint the provisioning
    // pins into the slot.
    let ephemeral = p256::SecretKey::from_slice(&EPHEMERAL_SCALAR).unwrap();
    let card_public = p256::PublicKey::from_sec1_bytes(card_point).unwrap();
    let shared = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), card_public.as_affine());
    let fingerprint = [0x77u8; 20];
    let param = ecdh::param(
        ecdh::CURVE_OID_P256,
        ecdh::ALG_ECDH,
        ecdh::HASH_SHA256,
        ecdh::KEK_AES128,
        &fingerprint,
    )
    .unwrap();
    let kek = ecdh::kdf(&param, shared.raw_secret_bytes().as_slice(), 16).unwrap();

    let session_key = fixture_session_key();
    let checksum = session_key
        .iter()
        .fold(0u16, |acc, byte| acc.wrapping_add(u16::from(*byte)));
    let mut m = heapless::Vec::<u8, 64>::new();
    m.push(7u8).unwrap();
    m.extend_from_slice(&session_key).unwrap();
    m.extend_from_slice(&checksum.to_be_bytes()).unwrap();
    m.resize(24, 0x05).unwrap();
    let wrapped = ecdh::aes_key_wrap(&kek, &m).unwrap();

    let mut import = vec![wrapped.len() as u8];
    import.extend_from_slice(&wrapped);
    import.push(ecdh::HASH_SHA256);
    import.push(ecdh::KEK_AES128);
    import.extend_from_slice(&fingerprint);
    let response = poll_response(
        &mut card,
        &mut rng,
        &xfr_frame(5, &frame(INS_PUT_DATA, 0x00, 0xD2, &import)),
    );
    let (_, sw) = apdu_response(&response);
    assert_eq!(sw, [0x90, 0x00], "PUT DATA D2 provisions the RFC 6637 mode");

    let response = poll_response(
        &mut card,
        &mut rng,
        &xfr_frame(6, &frame(INS_VERIFY, 0, 0x82, b"123456")),
    );
    let (_, sw) = apdu_response(&response);
    assert_eq!(sw, [0x90, 0x00], "PW1 verifies in mode 82");
    let baseline = saves.get();
    assert!(baseline > 0, "the provisioning persisted the slot");

    // --- (i) the largest decipherable frame: a full success -----------------
    let ceiling = MAX_MESSAGE_BYTES - frame_len(0);
    assert_eq!(
        frame_len(ceiling),
        MAX_MESSAGE_BYTES,
        "the formula pins the largest fitting frame"
    );
    assert_eq!(
        frame_len(ceiling + 1),
        MAX_MESSAGE_BYTES + 1,
        "one octet of frame more is already outside"
    );

    let boundary_message = vec![0x44u8; ceiling];
    let cipher = streamed_body(&fixture_session_key(), &boundary_message);
    assert_eq!(
        cipher.len(),
        boundary_message.len() + 40,
        "the streamed body is the message plus the CFB furniture"
    );
    assert!(
        cipher.len() <= pgp_sym::MAX_DATA,
        "the internal stream limit is the separate contract the adversarial suite freezes"
    );
    let command = point_command(&fixture_ephemeral_point(), Some(&cipher));
    let frame = xfr_frame(9, &decipher_apdu(&command));
    assert_eq!(
        frame.len(),
        MAX_MESSAGE_BYTES,
        "the boundary command exactly fills one CCID message"
    );

    let response = poll_response(&mut card, &mut rng, &frame);
    assert_eq!(response[0], RDR_TO_PC_DATA_BLOCK);
    let payload_len = u32::from_le_bytes(response[1..5].try_into().expect("a little-endian dword"));
    assert_eq!(
        payload_len,
        (ceiling + 2) as u32,
        "message plus status word"
    );
    assert_eq!(
        &response[ccid::HEADER_LEN..ccid::HEADER_LEN + ceiling],
        boundary_message.as_slice(),
        "byte-exact at the transport ceiling (AC-5 i)"
    );
    assert_eq!(&response[response.len() - 2..], &[0x90, 0x00]);

    // --- (ii) one octet of frame more: refused before the applet ------------
    let before_overflow = saves.get();
    let message = vec![0x44u8; ceiling + 1];
    let cipher = streamed_body(&fixture_session_key(), &message);
    let command = point_command(&fixture_ephemeral_point(), Some(&cipher));
    let frame = xfr_frame(10, &decipher_apdu(&command));
    assert_eq!(frame.len(), MAX_MESSAGE_BYTES + 1);

    assert!(
        matches!(card.feed(&frame), Err(CcidError::Overflow)),
        "the assembler refuses the over-ceiling frame (AC-5 ii)"
    );
    let mut out = [0u8; MAX_MESSAGE_BYTES];
    assert!(
        card.poll(&mut rng, &mut out)
            .expect("the card polls")
            .is_none(),
        "no status word, no bytes: the frame died in the assembler"
    );
    assert_eq!(
        saves.get(),
        before_overflow,
        "the overflowing command never reached the applet to save anything (AC-5 iii)"
    );

    // --- (iii) the applet never saw the command -----------------------------
    assert_eq!(
        applet.out.as_slice(),
        boundary_message.as_slice(),
        "the response buffer still holds the boundary answer: the over-ceiling frame never reached the applet (AC-5 iii)"
    );
}
