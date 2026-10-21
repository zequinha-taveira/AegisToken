//! Checks that the firmware-update vendor key of the environment can be used
//! in a release image.
//!
//! The build script of the firmware embeds the key; this helper applies the
//! same policy before the firmware is compiled, so a release build fails fast
//! instead of after the dependencies are built. It shares the policy with
//! `aegis-build-support`, so the development key is detected in one place.

use aegis_build_support::resolve_vendor_key;

fn main() {
    let value = std::env::var("AEGIS_UPDATE_VENDOR_PUBKEY").ok();
    match resolve_vendor_key(value.as_deref(), true) {
        Ok(_) => println!("vendor key accepted for a release image"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}
