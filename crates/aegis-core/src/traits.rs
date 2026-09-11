//! Hardware abstraction traits (PRD §28).
//!
//! The firmware layer consumes only these traits, never a concrete board or
//! vendor. Implementations live in `board-generic-rp2350`.

use crate::capabilities::DeviceCapabilities;
use crate::configuration::LedBehavior;
use crate::error::CoreError;
use crate::presence::UserPresence;

/// A controllable status LED.
pub trait Led {
    /// Set brightness, `0..=255`.
    fn set_brightness(&mut self, brightness: u8) -> Result<(), CoreError>;

    /// Set the behaviour policy.
    fn set_behavior(&mut self, behavior: LedBehavior) -> Result<(), CoreError>;
}

/// Byte-addressable persistent storage.
pub trait Storage {
    /// Read into `buf` starting at `offset`.
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), CoreError>;

    /// Write `data` starting at `offset`.
    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), CoreError>;

    /// Erase `len` bytes starting at `offset`.
    fn erase(&mut self, offset: u32, len: u32) -> Result<(), CoreError>;
}

impl<T: Storage + ?Sized> Storage for &mut T {
    fn read(&mut self, offset: u32, buf: &mut [u8]) -> Result<(), CoreError> {
        (**self).read(offset, buf)
    }

    fn write(&mut self, offset: u32, data: &[u8]) -> Result<(), CoreError> {
        (**self).write(offset, data)
    }

    fn erase(&mut self, offset: u32, len: u32) -> Result<(), CoreError> {
        (**self).erase(offset, len)
    }
}

/// Everything the firmware needs from a specific RP2350 board.
pub trait Rp2350Hardware {
    /// Capabilities discovered on this board.
    fn capabilities(&self) -> DeviceCapabilities;

    /// The presence source for FIDO operations.
    fn user_presence(&mut self) -> &mut dyn UserPresence;

    /// The status LED, when the board declares one.
    fn led(&mut self) -> Option<&mut dyn Led>;

    /// Persistent storage.
    fn storage(&mut self) -> &mut dyn Storage;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::presence::PresenceError;

    struct MockPresence;
    impl UserPresence for MockPresence {
        fn wait_for_presence(&mut self) -> Result<(), PresenceError> {
            Ok(())
        }
    }

    struct MockLed;
    impl Led for MockLed {
        fn set_brightness(&mut self, _brightness: u8) -> Result<(), CoreError> {
            Ok(())
        }
        fn set_behavior(&mut self, _behavior: LedBehavior) -> Result<(), CoreError> {
            Ok(())
        }
    }

    struct MockStorage;
    impl Storage for MockStorage {
        fn read(&mut self, _offset: u32, _buf: &mut [u8]) -> Result<(), CoreError> {
            Ok(())
        }
        fn write(&mut self, _offset: u32, _data: &[u8]) -> Result<(), CoreError> {
            Ok(())
        }
        fn erase(&mut self, _offset: u32, _len: u32) -> Result<(), CoreError> {
            Ok(())
        }
    }

    struct MockHardware {
        presence: MockPresence,
        led: MockLed,
        storage: MockStorage,
    }

    impl Rp2350Hardware for MockHardware {
        fn capabilities(&self) -> DeviceCapabilities {
            DeviceCapabilities::rp2350a()
        }
        fn user_presence(&mut self) -> &mut dyn UserPresence {
            &mut self.presence
        }
        fn led(&mut self) -> Option<&mut dyn Led> {
            Some(&mut self.led)
        }
        fn storage(&mut self) -> &mut dyn Storage {
            &mut self.storage
        }
    }

    #[test]
    fn traits_are_object_safe_and_usable() {
        let mut hw = MockHardware {
            presence: MockPresence,
            led: MockLed,
            storage: MockStorage,
        };
        assert_eq!(hw.capabilities().gpio_count, 30);
        assert!(hw.led().is_some());
        hw.storage().write(0, &[1, 2, 3]).unwrap();
        hw.user_presence().wait_for_presence().unwrap();
    }
}
