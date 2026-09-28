//! A kernel interface name, checked where it is parsed so everything past the configuration can
//! hand it to the kernel as is.

use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

use libc::c_char;
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// Non-empty and whitespace-free: a padded name would miss the interface with a confusing capture
/// error and slip past the `source_if`/`target_if` equality check. Shorter than `IF_NAMESIZE`, with
/// no colon or NUL: Linux resolves a longer name by its first bytes and cuts one at a colon, every
/// kernel ends one at a NUL, and each would land on another interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterfaceName(String);

impl InterfaceName {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// The kernel's fixed-size name field (`ifr_name`), zero-padded. The name always leaves room
    /// for the terminator, so this is also the name as a C string.
    #[must_use]
    pub(crate) fn to_c_array(&self) -> [c_char; libc::IF_NAMESIZE] {
        let mut field = [0; libc::IF_NAMESIZE];
        for (dst, &src) in field.iter_mut().zip(self.0.as_bytes()) {
            *dst = c_char::from_ne_bytes([src]);
        }
        field
    }
}

impl Deref for InterfaceName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum ParseInterfaceNameError {
    #[error("interface name must not be empty or contain whitespace")]
    Blank,
    #[error("interface name must be at most {max} bytes", max = libc::IF_NAMESIZE - 1)]
    TooLong,
    #[error("interface name must not contain ':', which names an address label, not an interface")]
    Colon,
    #[error("interface name must not contain a NUL byte")]
    Nul,
}

impl FromStr for InterfaceName {
    type Err = ParseInterfaceNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            return Err(ParseInterfaceNameError::Blank);
        }
        if s.len() >= libc::IF_NAMESIZE {
            return Err(ParseInterfaceNameError::TooLong);
        }
        if s.contains(':') {
            return Err(ParseInterfaceNameError::Colon);
        }
        if s.contains('\0') {
            return Err(ParseInterfaceNameError::Nul);
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interface::LOOPBACK_IFACE;

    impl InterfaceName {
        pub(crate) fn loopback() -> Self {
            LOOPBACK_IFACE
                .parse()
                .expect("the loopback's name is valid")
        }
    }

    #[test]
    fn interface_name_parses_via_fromstr() {
        assert_eq!("en0".parse::<InterfaceName>().unwrap().as_str(), "en0");
        assert_eq!(
            "".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError::Blank)
        );
        // Whitespace is rejected: a padded name misses the interface and dodges SameInterface.
        assert_eq!(
            " en0 ".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError::Blank)
        );
        assert_eq!(
            "e n0".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError::Blank)
        );
    }

    #[test]
    fn interface_name_refuses_a_name_too_long_for_an_interface() {
        let longest = "a".repeat(libc::IF_NAMESIZE - 1);
        assert!(longest.parse::<InterfaceName>().is_ok());
        assert_eq!(
            format!("{longest}a").parse::<InterfaceName>(),
            Err(ParseInterfaceNameError::TooLong)
        );
    }

    #[test]
    fn interface_name_refuses_a_colon() {
        assert_eq!(
            "eth0:1".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError::Colon)
        );
    }

    #[test]
    fn interface_name_refuses_a_nul() {
        assert_eq!(
            "lo0\0x".parse::<InterfaceName>(),
            Err(ParseInterfaceNameError::Nul)
        );
    }

    #[test]
    fn to_c_array_zero_pads_the_name() {
        let bytes = |name: &InterfaceName| name.to_c_array().map(|c| c.to_ne_bytes()[0]);
        let en0: InterfaceName = "en0".parse().unwrap();
        assert_eq!(bytes(&en0)[..4], *b"en0\0");
        let longest: InterfaceName = "a".repeat(libc::IF_NAMESIZE - 1).parse().unwrap();
        assert_eq!(bytes(&longest)[libc::IF_NAMESIZE - 1], 0);
    }
}
