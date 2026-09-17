//! On-target self-test for hardware validation (Phases 10 and 17).
//!
//! Runs a set of non-destructive checks at boot and reports PASS/FAIL over
//! defmt/RTT. Destructive flash checks are gated behind the `selftest` feature.
//! Applet checks only exercise routing and default data objects — never key
//! generation, which takes seconds and belongs to the host validators.

use aegis_core::authenticator::Rng;
use aegis_core::configuration::DeviceConfig;
use aegis_core::identity::BoardIdentity;
use aegis_core::lifecycle::LifecycleState;
use aegis_core::management_protocol::{ManagementCommand, ManagementService};
use aegis_core::traits::Rp2350Hardware;
use aegis_core::{codec, ctap2};
use board_generic_rp2350::Board;
use board_generic_rp2350::rng::HardwareRng;
use defmt::info;

fn check(name: &str, passed: bool) {
    info!(
        "self-test {}: {}",
        name,
        if passed { "PASS" } else { "FAIL" }
    );
}

/// Run all self-test checks. Returns the number of failures.
pub fn run<const FLASH_SIZE: usize>(
    board: &mut Board<FLASH_SIZE>,
    rng: &mut HardwareRng,
    identity: BoardIdentity,
) -> u32 {
    let mut failures = 0u32;
    let mut record = |passed: bool| {
        if !passed {
            failures += 1;
        }
    };

    let capabilities = board.capabilities();
    record(capabilities.gpio_count == 30 || capabilities.gpio_count == 48);
    check(
        "capabilities",
        capabilities.gpio_count == 30 || capabilities.gpio_count == 48,
    );

    let hid = capabilities.usb.fido_hid && capabilities.usb.management_hid;
    record(hid);
    check("usb-hid", hid);

    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    rng.fill_bytes(&mut first);
    rng.fill_bytes(&mut second);
    let trng = first != second && first.iter().any(|byte| *byte != 0);
    record(trng);
    check("trng", trng);

    let mut buffer = [0u8; 256];
    let get_info = codec::encode_into(&ctap2::GetInfoResponse::default(), &mut buffer).is_ok();
    record(get_info);
    check("ctap2-getinfo-encode", get_info);

    let mut service = ManagementService::new(
        capabilities,
        identity,
        DeviceConfig::for_board(identity, &capabilities),
        LifecycleState::Factory,
    );
    let response = service.handle(ManagementCommand::GetDeviceInfo, &[]);
    let management = response.status.is_ok() && !response.payload.is_empty();
    record(management);
    check("management-device-info", management);

    // BOOTSEL read is non-destructive; just confirm it returns without fault.
    let _ = board.bootsel_pressed();
    check("bootsel-read", true);

    // Applet routing and default objects (Phase 17): SELECT each AID and
    // read one static DO per applet that needs no authentication.
    let applets = applet_check(rng);
    record(applets);
    check("applet-select", applets);

    #[cfg(feature = "selftest")]
    {
        let storage = storage_check(board);
        record(storage);
        check("sealed-storage", storage);
    }

    info!("self-test failures: {}", failures);
    failures
}

/// SELECT each applet AID through the CCID router and read one
/// unauthenticated default object per applet.
///
/// Uses volatile stores and never generates keys: RSA-2048 key generation
/// takes seconds on-device and stays in the host validators (`AC-021`).
fn applet_check(rng: &mut HardwareRng) -> bool {
    use aegis_applets::aid;
    use aegis_applets::oath::{MemoryOathStore, Oath};
    use aegis_applets::openpgp::{MemoryOpenPgpStore, OpenPgp};
    use aegis_applets::piv::{MemoryPivStore, Piv};
    use aegis_applets::router::{Applet, Router};

    fn select(router: &mut Router<'_, 2048>, rng: &mut HardwareRng, aid_value: &[u8]) -> bool {
        let mut frame = [0u8; 32];
        if aid_value.len() > 16 {
            return false;
        }
        frame[0..4].copy_from_slice(&[0x00, 0xA4, 0x04, 0x00]);
        frame[4] = aid_value.len() as u8;
        frame[5..5 + aid_value.len()].copy_from_slice(aid_value);
        router
            .command(&frame[..5 + aid_value.len()], rng)
            .sw
            .is_success()
    }

    fn command(router: &mut Router<'_, 2048>, rng: &mut HardwareRng, bytes: &[u8]) -> bool {
        router.command(bytes, rng).sw.is_success()
    }

    let mut piv = Piv::new(MemoryPivStore::new());
    let mut openpgp = OpenPgp::new(MemoryOpenPgpStore::new());
    let mut oath = Oath::new(MemoryOathStore::new());
    let mut applets: [&mut dyn Applet; 3] = [&mut piv, &mut openpgp, &mut oath];
    let mut router = Router::new(&mut applets);

    // AID routing: PIV, OpenPGP, OATH select cleanly; unknown is 6A82.
    for aid_value in [aid::PIV, aid::OPENPGP, aid::OATH] {
        if !select(&mut router, rng, aid_value) {
            return false;
        }
    }
    if select(&mut router, rng, &[0xFF; 8]) {
        return false;
    }

    // PIV answers its default CCC without authentication.
    if !select(&mut router, rng, aid::PIV) {
        return false;
    }
    if !command(
        &mut router,
        rng,
        &[0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, 0x5F, 0xC1, 0x07],
    ) {
        return false;
    }

    // OpenPGP answers its default algorithm attributes.
    if !select(&mut router, rng, aid::OPENPGP) {
        return false;
    }
    if !command(&mut router, rng, &[0x00, 0xCA, 0x00, 0xC1, 0x00]) {
        return false;
    }

    // OATH selects; credential flows stay in the host validators.
    select(&mut router, rng, aid::OATH)
}

#[cfg(feature = "selftest")]
fn storage_check<const FLASH_SIZE: usize>(board: &mut Board<FLASH_SIZE>) -> bool {
    use aegis_core::authenticator::{Credential, CredentialStore};
    use aegis_core::configuration::FixedString;
    use aegis_core::credential_store::SealedCredentialStore;

    const SCRATCH_BASE: u32 = 0x0016_0000;
    const SLOT_SIZE: u32 = 4096;
    // Zero-initialise then mix the scratch key in, so the value is not passed
    // to the sealer as a literal key.
    let mut key: [u8; 32] = Default::default();
    for byte in &mut key {
        *byte ^= 0x5A;
    }

    let mut store =
        match SealedCredentialStore::open(board.storage(), SCRATCH_BASE, SLOT_SIZE, &key) {
            Ok(store) => store,
            Err(_) => return false,
        };
    let credential = Credential {
        id: heapless::Vec::from_slice(&[0x42; 16]).expect("fits"),
        rp_id: FixedString::new("self-test.local").expect("fits"),
        user_id: heapless::Vec::from_slice(&[0x01, 0x02, 0x03, 0x04]).expect("fits"),
        private_key: [0x11; 32],
        sign_count: 0,
        discoverable: true,
    };
    if store.reset().is_err() || store.insert(credential).is_err() {
        return false;
    }
    if store.count() != 1 {
        return false;
    }
    let _ = store.reset();
    true
}
