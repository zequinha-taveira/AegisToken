//! Pending assertion state for the CTAP2.1 `authenticatorGetNextAssertion` flow.
//!
//! The platform receives one credential per command and asks for the next one
//! while the authenticator still remembers the request. The pending state
//! belongs to the application that started the request: it is keyed by the
//! CTAPHID channel, so another application on the same host cannot continue
//! an assertion it never asked for.

use heapless::Vec;

use crate::authenticator::MAX_CREDENTIALS;
use crate::configuration::FixedString;

/// Maximum length of a relying party identifier.
const MAX_RP_ID_LEN: usize = 64;

/// A pending assertion, ready to be continued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAssertion {
    /// CTAPHID channel that started the request.
    channel: u32,
    /// Credentials that matched the request, in order.
    credentials: Vec<Vec<u8, 32>, MAX_CREDENTIALS>,
    /// Index of the next credential to return.
    index: usize,
    /// Relying party of the assertion.
    rp_id: FixedString<MAX_RP_ID_LEN>,
    /// Client data hash of the assertion.
    client_data_hash: [u8; 32],
    /// Whether user verification was performed.
    uv: bool,
}

/// The next credential of a pending assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextAssertion {
    /// Credential identifier to sign with.
    pub credential_id: Vec<u8, 32>,
    /// Relying party of the assertion.
    pub rp_id: FixedString<MAX_RP_ID_LEN>,
    /// Client data hash of the assertion.
    pub client_data_hash: [u8; 32],
    /// Whether user verification was performed.
    pub uv: bool,
}

impl PendingAssertion {
    /// Start a pending assertion for `channel`.
    #[must_use]
    pub fn begin(
        channel: u32,
        credentials: Vec<Vec<u8, 32>, MAX_CREDENTIALS>,
        rp_id: FixedString<MAX_RP_ID_LEN>,
        client_data_hash: [u8; 32],
        uv: bool,
    ) -> Self {
        Self {
            channel,
            credentials,
            index: 1,
            rp_id,
            client_data_hash,
            uv,
        }
    }

    /// The channel that owns this pending assertion.
    #[must_use]
    pub const fn channel(&self) -> u32 {
        self.channel
    }

    /// Whether another credential is waiting for `channel`.
    ///
    /// A request from another channel never consumes the pending state: the
    /// owner of the assertion can still continue it.
    pub fn next(&mut self, channel: u32) -> Option<NextAssertion> {
        if channel != self.channel {
            return None;
        }
        let credential_id = self.credentials.get(self.index).cloned()?;
        self.index += 1;
        Some(NextAssertion {
            credential_id,
            rp_id: self.rp_id.clone(),
            client_data_hash: self.client_data_hash,
            uv: self.uv,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credentials(count: usize) -> Vec<Vec<u8, 32>, MAX_CREDENTIALS> {
        let mut out: Vec<Vec<u8, 32>, MAX_CREDENTIALS> = Vec::new();
        for index in 0..count {
            let mut id = [0u8; 32];
            id[0] = index as u8;
            out.push(Vec::from_slice(&id).expect("fits")).expect("fits");
        }
        out
    }

    fn pending(channel: u32, count: usize) -> PendingAssertion {
        PendingAssertion::begin(
            channel,
            credentials(count),
            FixedString::new("example.com").expect("fits"),
            [0x11; 32],
            true,
        )
    }

    #[test]
    fn another_channel_cannot_continue_the_assertion() {
        let mut state = pending(0x1122_3344, 3);
        assert!(state.next(0x1122_3344).is_some());
        // A different application asks for the next credential.
        assert!(state.next(0x5566_7788).is_none());
        // The owner can still continue.
        assert!(state.next(0x1122_3344).is_some());
    }

    #[test]
    fn the_credentials_are_served_in_order() {
        let mut state = pending(1, 3);
        let first = state.next(1).expect("second credential");
        assert_eq!(first.credential_id[0], 1);
        let second = state.next(1).expect("third credential");
        assert_eq!(second.credential_id[0], 2);
        // The list is exhausted.
        assert!(state.next(1).is_none());
    }

    #[test]
    fn the_context_of_the_request_is_preserved() {
        let mut state = pending(7, 2);
        let next = state.next(7).expect("credential");
        assert_eq!(next.rp_id.as_str(), "example.com");
        assert_eq!(next.client_data_hash, [0x11; 32]);
        assert!(next.uv);
        assert_eq!(state.channel(), 7);
    }

    #[test]
    fn a_single_credential_has_no_continuation() {
        let mut state = pending(3, 1);
        assert!(state.next(3).is_none());
    }
}
