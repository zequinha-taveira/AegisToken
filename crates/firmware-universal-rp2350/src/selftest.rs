//! On-target self-test for hardware validation (Phase 10).
//!
//! Runs a set of non-destructive checks at boot and reports PASS/FAIL over
//! defmt/RTT. Destructive flash checks are gated behind the `selftest` feature.

use aegis_core::authenticator::Rng;
use aegis_core::configuration::DeviceConfig;
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
pub fn run<const FLASH_SIZE: usize>(board: &mut Board<FLASH_SIZE>, rng: &mut HardwareRng) -> u32 {
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
        DeviceConfig::official_defaults(),
        LifecycleState::Factory,
    );
    let response = service.handle(ManagementCommand::GetDeviceInfo, &[]);
    let management = response.status.is_ok() && !response.payload.is_empty();
    record(management);
    check("management-device-info", management);

    // BOOTSEL read is non-destructive; just confirm it returns without fault.
    let _ = board.bootsel_pressed();
    check("bootsel-read", true);

    #[cfg(feature = "selftest")]
    {
        let storage = storage_check(board, rng);
        record(storage);
        check("sealed-storage", storage);
    }

    info!("self-test failures: {}", failures);
    failures
}

#[cfg(feature = "selftest")]
fn storage_check<const FLASH_SIZE: usize>(board: &mut Board<FLASH_SIZE>, rng: &mut HardwareRng) -> bool {
    use aegis_core::authenticator::{Credential, CredentialStore};
    use aegis_core::configuration::FixedString;
    use aegis_core::credential_store::SealedCredentialStore;

    const SCRATCH_BASE: u32 = 0x0016_0000;
    const SLOT_SIZE: u32 = 4096;
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);

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
