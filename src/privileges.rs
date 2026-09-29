//! Dropping root once the captures are open (the `user` setting).
//!
//! Started as root, the process switches to the account (supplementary groups cleared, then the
//! group, then the user) and refuses to run if root could still be regained. On Linux it also
//! settles its capabilities (the Linux-only `caps` module): none, or `CAP_NET_RAW` alone where this
//! kernel still needs it to pin DIAL connections to their interface.

#[cfg(target_os = "linux")]
mod caps;

use std::ffi::CString;
use std::io;
use std::mem::MaybeUninit;
use std::ptr;

use libc::{c_char, c_int, gid_t, uid_t};
use thiserror::Error;

use crate::config::{Principal, RunAs};
use crate::interface::InterfaceName;
use crate::sys::check;

/// A numeric identity: the one to switch to, or an account's uid and primary group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Credentials {
    pub(crate) uid: uid_t,
    pub(crate) gid: gid_t,
}

#[derive(Debug, Error)]
pub(crate) enum PrivilegeError {
    #[error("no user named \"{0}\"")]
    UnknownUser(String),
    #[error("no group named \"{0}\"")]
    UnknownGroup(String),
    #[error("uid {0} has no account to take its group from; name the group as USER:GROUP")]
    NoPrimaryGroup(u32),
    #[error("the account must be unprivileged, not uid 0 or gid 0")]
    Privileged,
    #[error("started as uid {0}, not root, so it cannot switch to another account")]
    NotRoot(u32),
    #[error("cannot look up the account: {0}")]
    Lookup(io::Error),
    #[error("{step} failed: {source}")]
    Drop {
        step: &'static str,
        source: io::Error,
    },
    #[error("root privileges survived the switch; refusing to run")]
    StillPrivileged,
    #[cfg(target_os = "linux")]
    #[error("capabilities beyond the chosen ones survived the switch; refusing to run")]
    CapabilitiesSurvived,
    #[cfg(target_os = "linux")]
    #[error(
        "the process does not hold {0}, which the switch needs; a container runtime may withhold it"
    )]
    Withheld(&'static str),
}

/// How the process came to run as the account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Switch {
    /// Started as root: now that account, supplementary groups cleared, root not regainable.
    Dropped,
    /// Started as that account already, so there was no account to change.
    AlreadyThatAccount,
}

/// What the switch decided about DIAL's interface pin. Every capability but `CAP_NET_RAW` is gone
/// on Linux whatever the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialPin {
    /// Nothing to decide: no DIAL entry, or a platform whose pin needs no capability.
    NoDial,
    /// This kernel pins without `CAP_NET_RAW`, so nothing was kept.
    #[cfg(target_os = "linux")]
    Unprivileged,
    /// `CAP_NET_RAW` kept, alone: this kernel needs it for the pin, or that could not be told.
    #[cfg(target_os = "linux")]
    KeptNetRaw,
    /// The pin needs `CAP_NET_RAW` (or that could not be told) and the process does not hold it,
    /// so DIAL connections fail; a warning says so.
    #[cfg(target_os = "linux")]
    NotHeld,
}

/// What [`drop_to`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) switch: Switch,
    pub(crate) dial_pin: DialPin,
}

/// The numeric identity `run_as` names. A named user brings its primary group unless the setting
/// names one; a bare uid takes the group of the account behind it.
///
/// # Errors
/// [`PrivilegeError`] for an unknown account, or one that is root.
pub(crate) fn resolve(run_as: &RunAs) -> Result<Credentials, PrivilegeError> {
    // A number is taken as is: the database is consulted only for a name, or for the group of a
    // bare uid, so a setting in numbers works where there is no /etc/passwd at all.
    let (uid, primary) = match run_as.user() {
        Principal::Id(uid) => (*uid, None),
        Principal::Name(name) => {
            let account =
                user_by_name(name)?.ok_or_else(|| PrivilegeError::UnknownUser(name.clone()))?;
            (account.uid, Some(account.gid))
        }
    };
    let gid = match (run_as.group(), primary) {
        (Some(Principal::Id(gid)), _) => *gid,
        (Some(Principal::Name(name)), _) => {
            group_by_name(name)?.ok_or_else(|| PrivilegeError::UnknownGroup(name.clone()))?
        }
        (None, Some(gid)) => gid,
        (None, None) => user_by_id(uid)?
            .map(|account| account.gid)
            .ok_or(PrivilegeError::NoPrimaryGroup(uid))?,
    };
    if uid == 0 || gid == 0 {
        return Err(PrivilegeError::Privileged);
    }
    Ok(Credentials { uid, gid })
}

/// Run as `credentials` from here on. Started as root, switch the whole process to them,
/// supplementary groups cleared; started as that account already, keep it. Either way, on Linux
/// keep no capability but `CAP_NET_RAW`, and that only when `dial` (a DIAL entry's target
/// interface) cannot be pinned without it on this kernel. Then prove the result: the ids read back
/// as asked, `setuid(0)` fails, and on Linux the capability sets are exactly the chosen ones.
///
/// # Errors
/// [`PrivilegeError`] if the switch is refused or does not take.
pub(crate) fn drop_to(
    credentials: Credentials,
    dial: Option<&InterfaceName>,
) -> Result<Outcome, PrivilegeError> {
    let effective = effective_ids();
    let switch = if effective.uid == 0 {
        // Down to what the switch and the decision after it need, while still root, so the
        // permitted set kept across the uid change carries nothing else of root's.
        #[cfg(target_os = "linux")]
        caps::narrow_for_switch(dial.is_some())?;
        switch_to(credentials)?;
        Switch::Dropped
    } else if effective == credentials && real_ids() == credentials {
        Switch::AlreadyThatAccount
    } else {
        return Err(PrivilegeError::NotRoot(effective.uid));
    };
    #[cfg(target_os = "linux")]
    let dial_pin = caps::settle(dial)?;
    #[cfg(not(target_os = "linux"))]
    let dial_pin = {
        // Only Linux gates the interface pin on a capability.
        let _ = dial;
        DialPin::NoDial
    };
    // SAFETY: setuid takes a plain id; this call must fail.
    let regained = unsafe { libc::setuid(0) } == 0;
    if regained || effective_ids() != credentials || real_ids() != credentials {
        return Err(PrivilegeError::StillPrivileged);
    }
    Ok(Outcome { switch, dial_pin })
}

/// Groups first: once the uid is gone, so is the right to change them.
fn switch_to(credentials: Credentials) -> Result<(), PrivilegeError> {
    let drop = |step, rc| check(rc).map_err(|source| PrivilegeError::Drop { step, source });
    // SAFETY: setgroups reads one gid from a live array.
    drop("setgroups", unsafe {
        libc::setgroups(1, &raw const credentials.gid)
    })?;
    // SAFETY: setgid/setuid take plain ids.
    drop("setgid", unsafe { libc::setgid(credentials.gid) })?;
    // SAFETY: as above.
    drop("setuid", unsafe { libc::setuid(credentials.uid) })
}

fn effective_ids() -> Credentials {
    // SAFETY: geteuid/getegid take no arguments and cannot fail.
    unsafe {
        Credentials {
            uid: libc::geteuid(),
            gid: libc::getegid(),
        }
    }
}

fn real_ids() -> Credentials {
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    unsafe {
        Credentials {
            uid: libc::getuid(),
            gid: libc::getgid(),
        }
    }
}

fn user_by_name(name: &str) -> Result<Option<Credentials>, PrivilegeError> {
    let Ok(name) = CString::new(name) else {
        return Ok(None);
    };
    lookup(
        // SAFETY: every pointer is live for the call and `len` is the buffer's length.
        |entry, buf, len, found| unsafe { libc::getpwnam_r(name.as_ptr(), entry, buf, len, found) },
        account_of,
    )
}

fn user_by_id(uid: uid_t) -> Result<Option<Credentials>, PrivilegeError> {
    lookup(
        // SAFETY: as in user_by_name.
        |entry, buf, len, found| unsafe { libc::getpwuid_r(uid, entry, buf, len, found) },
        account_of,
    )
}

/// The uid and primary group a password entry names.
fn account_of(entry: &libc::passwd) -> Credentials {
    Credentials {
        uid: entry.pw_uid,
        gid: entry.pw_gid,
    }
}

fn group_by_name(name: &str) -> Result<Option<gid_t>, PrivilegeError> {
    let Ok(name) = CString::new(name) else {
        return Ok(None);
    };
    lookup(
        // SAFETY: as in user_by_name.
        |entry, buf, len, found| unsafe { libc::getgrnam_r(name.as_ptr(), entry, buf, len, found) },
        |entry: &libc::group| entry.gr_gid,
    )
}

/// Where a lookup buffer stops growing: far past any real account entry, short of unbounded.
const MAX_LOOKUP_BUFFER: usize = 1 << 20;

/// Run a reentrant account lookup, growing its buffer while it reports `ERANGE`, and keep only
/// what `pick` copies out: the entry's strings live in the buffer, which does not outlive this.
fn lookup<T, R>(
    call: impl Fn(*mut T, *mut c_char, usize, *mut *mut T) -> c_int,
    pick: impl Fn(&T) -> R,
) -> Result<Option<R>, PrivilegeError> {
    let mut len = 1024;
    loop {
        let mut buf: Vec<c_char> = vec![0; len];
        let mut entry = MaybeUninit::<T>::uninit();
        let mut found: *mut T = ptr::null_mut();
        let rc = call(entry.as_mut_ptr(), buf.as_mut_ptr(), len, &raw mut found);
        if rc == libc::ERANGE && len < MAX_LOOKUP_BUFFER {
            len *= 2;
            continue;
        }
        // POSIX lets "not found" come back as one of these rather than a null result (musl
        // says ENOENT when the database file itself is absent, as in a scratch image).
        match rc {
            0 => {}
            libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM => return Ok(None),
            _ => return Err(PrivilegeError::Lookup(io::Error::from_raw_os_error(rc))),
        }
        if found.is_null() {
            return Ok(None);
        }
        // SAFETY: a non-null result points at `entry`, which the call filled in.
        return Ok(Some(pick(unsafe { &*found })));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whether this process is root, where a real drop would de-privilege the whole test run.
    fn is_root() -> bool {
        // SAFETY: geteuid takes no arguments and cannot fail.
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn numbers_resolve_as_given() {
        let credentials = resolve(&"65534:65533".parse().unwrap()).unwrap();
        assert_eq!(
            credentials,
            Credentials {
                uid: 65534,
                gid: 65533
            }
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn a_name_resolves_through_the_account_database() {
        // Every target has `nobody`: 65534 on Linux and FreeBSD, -2 on macOS.
        let credentials = resolve(&"nobody".parse().unwrap()).unwrap();
        assert_ne!(credentials.uid, 0);
        assert_ne!(credentials.gid, 0);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn an_unknown_account_is_refused_by_name() {
        assert!(matches!(
            resolve(&"no-such-user-nf".parse().unwrap()),
            Err(PrivilegeError::UnknownUser(name)) if name == "no-such-user-nf"
        ));
        assert!(matches!(
            resolve(&"nobody:no-such-group-nf".parse().unwrap()),
            Err(PrivilegeError::UnknownGroup(name)) if name == "no-such-group-nf"
        ));
        // A bare number with no account behind it has no group to take.
        assert!(matches!(
            resolve(&"3999999".parse().unwrap()),
            Err(PrivilegeError::NoPrimaryGroup(3_999_999))
        ));
    }

    #[test]
    fn a_missing_account_database_reads_as_no_account() {
        // POSIX lets the *_r lookups report "not found" as one of these instead of a null result;
        // musl does, with ENOENT, where /etc/passwd is absent (a scratch container image).
        for code in [libc::ENOENT, libc::ESRCH, libc::EBADF, libc::EPERM] {
            let found = lookup(|_, _, _, _| code, |entry: &libc::passwd| entry.pw_uid).unwrap();
            assert_eq!(found, None, "errno {code}");
        }
        assert!(matches!(
            lookup(|_, _, _, _| libc::EIO, |entry: &libc::passwd| entry.pw_uid),
            Err(PrivilegeError::Lookup(_))
        ));
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn root_is_refused_as_a_target() {
        for spec in ["0", "root", "0:0", "65534:0"] {
            assert!(
                matches!(
                    resolve(&spec.parse().unwrap()),
                    Err(PrivilegeError::Privileged)
                ),
                "{spec}"
            );
        }
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "calls the account database or process ids through libc, which Miri cannot run"
    )]
    fn a_non_root_process_keeps_its_own_account_and_refuses_another() {
        if is_root() {
            return; // Covered end to end: a drop here would de-privilege the test run.
        }
        let own = real_ids();
        assert_eq!(
            drop_to(own, None).unwrap(),
            Outcome {
                switch: Switch::AlreadyThatAccount,
                dial_pin: DialPin::NoDial,
            }
        );
        let other = Credentials {
            uid: own.uid + 1,
            gid: own.gid,
        };
        assert!(
            matches!(drop_to(other, None), Err(PrivilegeError::NotRoot(uid)) if uid == own.uid)
        );
    }
}
