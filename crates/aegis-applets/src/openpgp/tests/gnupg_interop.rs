//! Interoperability of the OpenPGP ECDH decryption with GnuPG.
//!
//! The applet is driven as if it were the card, and the real GnuPG plays the
//! sender: GnuPG generates the ECDH key, encrypts a message to it and the
//! card decrypts the message with the RFC 6637 section 8 flow. The whole chain is
//! exercised against a real implementation: the KDF parameters, the KDF, the
//! AES key wrap and the OpenPGP symmetric layer.
//!
//! The test is skipped when GnuPG is not installed or only emits AEAD packets,
//! which the applet does not support yet. Set `AEGIS_GPG` to select the binary.

use std::path::PathBuf;
use std::process::{Command, Output};

use super::*;
use std::vec::Vec;

/// The curve OID of P-256, as it appears in a public key packet.
const OID_P256_BYTES: [u8; 8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// A TLV with a short length.
fn tlv_bytes(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = vec![tag, value.len() as u8];
    out.extend_from_slice(value);
    out
}

/// The GnuPG executable, when it is available.
fn gpg_path() -> Option<PathBuf> {
    if let Ok(path) = std::env::var("AEGIS_GPG") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    for candidate in [
        "gpg",
        "/usr/bin/gpg",
        "/usr/local/bin/gpg",
        "C:\\Program Files\\Git\\usr\\bin\\gpg.exe",
    ] {
        let path = PathBuf::from(candidate);
        if path.exists() {
            return Some(path);
        }
    }
    None
}

/// Run GnuPG in the given home directory.
///
/// The home directory is relative on purpose: the agent of GnuPG derives the
/// name of its socket from it, and an absolute Windows path carries a colon
/// that the agent refuses.
fn run_gpg(home: &str, args: &[&str]) -> Output {
    Command::new(gpg_path().expect("GnuPG is available"))
        .arg("--homedir")
        .arg(home)
        .arg("--batch")
        .arg("--yes")
        .arg("--no-tty")
        .arg("--pinentry-mode")
        .arg("loopback")
        .arg("--passphrase")
        .arg("")
        .args(args)
        .output()
        .expect("GnuPG runs")
}

/// The packets of an OpenPGP message.
struct Packet {
    tag: u8,
    body: Vec<u8>,
}

/// Split an OpenPGP message into its packets (both the old and the new
/// packet formats: GnuPG exports secret keys in the old format).
fn walk_packets(data: &[u8]) -> Vec<Packet> {
    let mut packets = Vec::new();
    let mut index = 0;
    while index < data.len() {
        let header = data[index];
        index += 1;
        let (tag, length) = if header & 0x40 != 0 {
            let tag = header & 0x3F;
            let length = match data[index] {
                0..=191 => {
                    let length = data[index] as usize;
                    index += 1;
                    length
                }
                192..=254 => {
                    let length =
                        ((data[index] as usize - 192) << 8) + data[index + 1] as usize + 192;
                    index += 2;
                    length
                }
                _ => {
                    let length = u32::from_be_bytes([
                        data[index + 1],
                        data[index + 2],
                        data[index + 3],
                        data[index + 4],
                    ]) as usize;
                    index += 5;
                    length
                }
            };
            (tag, length)
        } else {
            // The old format carries the tag in the four low bits of the
            // header and the length in one of four widths.
            let tag = (header >> 2) & 0x0F;
            let length = match header & 0x03 {
                0 => {
                    let length = data[index] as usize;
                    index += 1;
                    length
                }
                1 => {
                    let length = u16::from_be_bytes([data[index], data[index + 1]]) as usize;
                    index += 2;
                    length
                }
                2 => {
                    let length = u32::from_be_bytes([
                        data[index],
                        data[index + 1],
                        data[index + 2],
                        data[index + 3],
                    ]) as usize;
                    index += 4;
                    length
                }
                _ => data.len() - index,
            };
            (tag, length)
        };
        packets.push(Packet {
            tag,
            body: data[index..index + length].to_vec(),
        });
        index += length;
    }
    packets
}

/// Read a multiprecision integer: two octets of bit length and the value.
fn read_mpi(data: &[u8], offset: usize) -> (Vec<u8>, usize) {
    let bits = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
    let length = bits.div_ceil(8);
    (
        data[offset + 2..offset + 2 + length].to_vec(),
        offset + 2 + length,
    )
}

/// The ECDH key of a secret key export: the curve, the public point, the KDF
/// parameters and the private scalar.
struct EcdhKey {
    point: Vec<u8>,
    kdf: Vec<u8>,
    secret: Vec<u8>,
}

/// Extract the ECDH P-256 key from an exported secret key.
fn ecdh_key_from_export(data: &[u8]) -> EcdhKey {
    for packet in walk_packets(data) {
        if packet.tag != 7 {
            continue;
        }
        let body = packet.body;
        let mut offset = 1 + 4 + 1; // version, creation time, algorithm
        let oid_len = body[offset] as usize;
        offset += 1;
        if body[offset..offset + oid_len] != OID_P256_BYTES {
            continue;
        }
        offset += oid_len;
        let (point, next) = read_mpi(&body, offset);
        offset = next;
        // The KDF parameters are a raw field (RFC 6637 section 9), not an MPI.
        let kdf = body[offset..offset + 4].to_vec();
        offset += 4;
        // The S2K usage: 0x00 means the secret is not protected.
        assert_eq!(body[offset], 0x00, "the secret key is not protected");
        offset += 1;
        let (secret, _) = read_mpi(&body, offset);
        return EcdhKey { point, kdf, secret };
    }
    panic!("the export has no ECDH P-256 secret key");
}

/// The fingerprint of a key, as GnuPG prints it.
fn gpg_fingerprint(home: &str) -> String {
    let listing = run_gpg(home, &["--list-keys", "--with-colons"]);
    let text = String::from_utf8_lossy(&listing.stdout).to_string();
    text.lines()
        .filter(|line| line.starts_with("fpr:"))
        .filter_map(|line| line.split(':').nth(9))
        .map(str::to_string)
        .next()
        .expect("the key has a fingerprint")
}

#[test]
fn gnupg_encrypts_and_the_card_decrypts() {
    let Some(_) = gpg_path() else {
        eprintln!("GnuPG is not installed: skipping the interoperability test");
        return;
    };
    let home = format!("../../target/gnupg-interop-{}", std::process::id());
    let _ = std::fs::remove_dir_all(&home);
    std::fs::create_dir_all(&home).expect("the home directory is created");

    // --- GnuPG generates the key of the card --------------------------------
    let output = run_gpg(
        &home,
        &[
            "--rfc4880",
            "--quick-generate-key",
            "AegisToken Interop <interop@aegistoken.local>",
            "default",
            "default",
        ],
    );
    assert!(
        output.status.success(),
        "GnuPG generates the primary key: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let primary = gpg_fingerprint(&home);
    let output = run_gpg(&home, &["--quick-add-key", &primary, "nistp256", "encr"]);
    assert!(
        output.status.success(),
        "GnuPG adds the ECDH P-256 subkey: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // The subkey is the last one: its fingerprint is the one of the card.
    let listing = run_gpg(&home, &["--list-keys", "--with-colons"]);
    let text = String::from_utf8_lossy(&listing.stdout).to_string();
    let fingerprints: Vec<String> = text
        .lines()
        .filter(|line| line.starts_with("fpr:"))
        .filter_map(|line| line.split(':').nth(9))
        .map(str::to_string)
        .collect();
    let subkey = fingerprints
        .last()
        .cloned()
        .expect("the subkey has a fingerprint");

    // The secret key of the card comes from GnuPG.
    let export = run_gpg(&home, &["--export-secret-keys", &subkey]);
    assert!(export.status.success(), "the secret key is exported");
    let key = ecdh_key_from_export(&export.stdout);
    assert_eq!(key.point.len(), 65, "an uncompressed P-256 point");
    assert_eq!(key.kdf, vec![0x03, 0x01, 0x08, 0x07], "SHA-256 and AES-128");
    assert_eq!(key.secret.len(), 32, "the private scalar");

    // --- The card holds that key -------------------------------------------
    let mut applet = OpenPgp::new(MemoryOpenPgpStore::new());
    applet.select();
    let mut material = [0u8; SLOT_MATERIAL_BYTES];
    material[..32].copy_from_slice(&key.secret);
    applet.keys[1] = KeySlot {
        present: true,
        len: 32,
        algo: KEY_ALGO_ECDH_P256,
        material,
    };

    // The fingerprint of the key covers its creation time. The card has no
    // clock (it computes fingerprints with a zero creation time), so it cannot
    // guess the value that the sender put in the KDF parameters: the sender
    // provisions it with the wrapped session key.
    let computed = applet.fingerprint(1).expect("the card has a fingerprint");
    let mut computed_hex = String::new();
    for byte in computed {
        computed_hex.push_str(&format!("{byte:02X}"));
    }
    assert_ne!(
        computed_hex, subkey,
        "a fingerprint covers the creation time of the key"
    );
    let mut recipient = [0u8; 20];
    for (index, byte) in recipient.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&subkey[index * 2..index * 2 + 2], 16).expect("a hex digit");
    }

    // --- GnuPG encrypts to the card ----------------------------------------
    let message = b"AegisToken GnuPG interoperability";
    let plain_file = format!("{home}/message.txt");
    let cipher_file = format!("{home}/message.gpg");
    std::fs::write(&plain_file, message).expect("the message is written");
    let output = run_gpg(
        &home,
        &[
            "--rfc4880",
            "--force-mdc",
            "--trust-model",
            "always",
            "--compress-algo",
            "none",
            "--recipient",
            &format!("{subkey}!"),
            "--output",
            &cipher_file,
            "--encrypt",
            &plain_file,
        ],
    );
    assert!(
        output.status.success(),
        "GnuPG encrypts to the card: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let encrypted = std::fs::read(&cipher_file).expect("the message is read");

    // The ephemeral key and the wrapped session key of the message.
    let mut ephemeral = Vec::new();
    let mut wrapped = Vec::new();
    let mut ciphertext = Vec::new();
    for packet in walk_packets(&encrypted) {
        match packet.tag {
            1 => {
                // Public key encrypted session key: version, key id, algorithm,
                // the ephemeral key and the wrapped session key.
                let body = packet.body;
                let (point, offset) = read_mpi(&body, 10);
                ephemeral = point;
                let size = body[offset] as usize;
                wrapped = body[offset + 1..offset + 1 + size].to_vec();
            }
            18 => {
                // The encrypted data packet: the version and the ciphertext.
                ciphertext = packet.body[1..].to_vec();
            }
            _ => {}
        }
    }
    if ciphertext.is_empty()
        && walk_packets(&encrypted)
            .iter()
            .any(|packet| packet.tag == 20)
    {
        eprintln!("GnuPG selected AEAD (tag 20), which the applet does not support: skipping");
        return;
    }
    assert_eq!(ephemeral.len(), 65, "the ephemeral key is a point");
    assert!(!wrapped.is_empty(), "the session key is wrapped");
    assert!(
        !ciphertext.is_empty(),
        "the data is encrypted; GnuPG packet tags: {:?}",
        walk_packets(&encrypted)
            .iter()
            .map(|packet| packet.tag)
            .collect::<Vec<_>>()
    );

    // --- The card decrypts --------------------------------------------------
    let mut rng = TestRng(1);
    let mut send = |apdu: &[u8]| -> (Vec<u8>, Sw) {
        let command = Apdu::parse(apdu).expect("the APDU parses");
        let response = applet.process(&command, &mut rng);
        (response.data.to_vec(), response.sw)
    };

    let (_, sw) = send(&frame(0x20, 0x00, 0x83, b"12345678"));
    assert_eq!(sw, Sw::OK, "PW3 is verified");
    let (_, sw) = send(&frame(0x20, 0x00, 0x82, b"123456"));
    assert_eq!(sw, Sw::OK, "PW1 is verified in mode 82");

    // The host provisions the session key already wrapped, as the card-side
    // mode of RFC 6637 section 8 expects.
    let mut import = vec![wrapped.len() as u8];
    import.extend_from_slice(&wrapped);
    import.extend_from_slice(&key.kdf[2..4]);
    let (_, sw) = send(&frame(0xDA, 0x00, 0xD2, &import));
    assert_eq!(sw, Sw::OK, "the wrapped session key is provisioned");

    let mut command = tlv_bytes(0x86, &ephemeral);
    command.extend_from_slice(&tlv_bytes(0x80, &ciphertext));

    // Without the fingerprint of the sender the KDF parameters differ and the
    // session key does not unwrap: the card fails closed.
    let (_, sw) = send(&frame(0x2A, 0x80, 0x86, &command));
    assert_ne!(sw, Sw::OK, "the card does not guess the KDF parameters");

    // With the fingerprint of the sender the card decrypts on its own.
    import.extend_from_slice(&recipient);
    let (_, sw) = send(&frame(0xDA, 0x00, 0xD2, &import));
    assert_eq!(
        sw,
        Sw::OK,
        "the wrapped session key and the fingerprint are provisioned"
    );
    let (plain, sw) = send(&frame(0x2A, 0x80, 0x86, &command));
    assert_eq!(sw, Sw::OK, "the card decrypts the message");

    // The plaintext of the card is the literal data packet of the message.
    // GnuPG writes it in the old packet format: tag 11, a one-octet length,
    // the format octet, the file name, the date and the data itself.
    assert_eq!(plain[0], 0xAC, "an old format literal data packet");
    let name_length = plain[3] as usize;
    let data = &plain[4 + name_length + 4..];
    assert_eq!(data, message, "the card returns the plaintext");

    // A KDF hash outside the implemented domain is refused at the border and
    // the valid material keeps working: the refusal wrote nothing.
    let mut foreign = import.clone();
    foreign[1 + wrapped.len()] = 0x0A;
    let (_, sw) = send(&frame(0xDA, 0x00, 0xD2, &foreign));
    assert_eq!(sw, Sw::WRONG_DATA, "SHA-512 is not a supported KDF hash");
    let (again, sw) = send(&frame(0x2A, 0x80, 0x86, &command));
    assert_eq!(sw, Sw::OK, "the provisioned material still decrypts");
    assert_eq!(again, plain, "the same plaintext comes back");

    // --- GnuPG decrypts the same message -----------------------------------
    let output = run_gpg(&home, &["--decrypt", &cipher_file]);
    assert!(
        output.status.success(),
        "GnuPG decrypts: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, message, "GnuPG returns the plaintext");

    let _ = std::fs::remove_dir_all(&home);
}
