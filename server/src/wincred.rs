//! Generic credentials in the Windows Credential Manager, written the way `go-keyring` writes them
//! so either side reads what the other wrote: the secret as raw bytes, persisted per machine.
#![cfg(windows)]

use std::io;
use std::ptr;
use std::slice;

use credrelay_protocol::{Credential, CredentialStore, Failure};
use windows_sys::Win32::Foundation::ERROR_NOT_FOUND;
use windows_sys::Win32::Security::Credentials::{
    CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC, CREDENTIALW, CredDeleteW, CredEnumerateW,
    CredFree, CredReadW, CredWriteW,
};
use windows_sys::core::{BOOL, PWSTR};

pub struct WinCred;

impl CredentialStore for WinCred {
    fn read(&self, target: &str) -> Result<Vec<u8>, Failure> {
        let target = wide(target);
        let mut credential: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `target` is NUL-terminated and outlives the call; on success the API hands back
        // a buffer that `Owned` frees.
        check(unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut credential) })?;
        let credential = Owned(credential);
        // SAFETY: a successful CredReadW leaves `credential` pointing at a valid CREDENTIALW.
        Ok(unsafe { blob(&*credential.0) }.to_vec())
    }

    fn write(&self, target: &str, username: &str, secret: &[u8]) -> Result<(), Failure> {
        let mut target = wide(target);
        let mut username = wide(username);
        let blob_size = u32::try_from(secret.len())
            .map_err(|_| Failure::Store("secret is too large".into()))?;
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            UserName: username.as_mut_ptr(),
            CredentialBlobSize: blob_size,
            CredentialBlob: secret.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            ..Default::default()
        };
        // SAFETY: every pointer in `credential` points into a buffer alive for the call, and
        // CredWriteW only reads them.
        check(unsafe { CredWriteW(&credential, 0) })
    }

    fn delete(&self, target: &str) -> Result<(), Failure> {
        let target = wide(target);
        // SAFETY: `target` is NUL-terminated and outlives the call.
        check(unsafe { CredDeleteW(target.as_ptr(), CRED_TYPE_GENERIC, 0) })
    }

    fn list(&self, prefix: &str) -> Result<Vec<Credential>, Failure> {
        // The filter matches case-insensitively, and `*` is its own wildcard anywhere in the
        // prefix; the exact comparison below keeps only what the caller asked for.
        let filter = wide(&format!("{prefix}*"));
        let mut count = 0u32;
        let mut credentials: *mut *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `filter` is NUL-terminated and outlives the call; on success the API hands back
        // one buffer holding `count` credentials, which `Owned` frees.
        match check(unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut credentials) }) {
            Ok(()) => {}
            Err(Failure::NotFound) => return Ok(Vec::new()),
            Err(failure) => return Err(failure),
        }
        let credentials = Owned(credentials);
        // SAFETY: a successful CredEnumerateW leaves `count` valid pointers behind `credentials`.
        let listed = unsafe { slice::from_raw_parts(credentials.0, count as usize) };
        Ok(listed
            .iter()
            // SAFETY: each listed pointer is a valid CREDENTIALW inside the owned buffer.
            .map(|&credential| unsafe { &*credential })
            .filter(|credential| credential.Type == CRED_TYPE_GENERIC)
            .map(|credential| Credential {
                // SAFETY: TargetName and UserName are NUL-terminated or null.
                target: unsafe { string(credential.TargetName) },
                username: unsafe { string(credential.UserName) },
            })
            .filter(|credential| credential.target.starts_with(prefix))
            .collect())
    }
}

/// A buffer the Credential Manager allocated, freed when dropped.
struct Owned<T>(*mut T);

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        // SAFETY: the pointer came from a successful Cred* call and is freed exactly once.
        unsafe { CredFree(self.0.cast()) }
    }
}

fn check(succeeded: BOOL) -> Result<(), Failure> {
    if succeeded != 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
        Err(Failure::NotFound)
    } else {
        Err(Failure::Store(error.to_string()))
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// # Safety
///
/// `credential.CredentialBlob` must point at `CredentialBlobSize` readable bytes, or be null.
unsafe fn blob(credential: &CREDENTIALW) -> &[u8] {
    if credential.CredentialBlob.is_null() {
        return &[];
    }
    // SAFETY: guaranteed by the caller.
    unsafe {
        slice::from_raw_parts(
            credential.CredentialBlob,
            credential.CredentialBlobSize as usize,
        )
    }
}

/// # Safety
///
/// `text` must be a NUL-terminated UTF-16 string, or null.
unsafe fn string(text: PWSTR) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: guaranteed by the caller.
    unsafe {
        let len = (0..).take_while(|&i| *text.add(i) != 0).count();
        String::from_utf16_lossy(slice::from_raw_parts(text, len))
    }
}

/// These run against the real Credential Manager of whoever runs them, under a target prefix of
/// their own that no application uses, and delete what they write.
#[cfg(test)]
mod tests {
    use super::*;

    fn target(name: &str) -> String {
        format!("credrelay-test:{}:{name}", std::process::id())
    }

    #[test]
    fn a_written_credential_reads_back_and_deletes() {
        let target = target("round-trip");
        WinCred.write(&target, "octo", b"t0ken").unwrap();
        assert_eq!(WinCred.read(&target).unwrap(), b"t0ken");
        WinCred.delete(&target).unwrap();
        assert_eq!(WinCred.read(&target), Err(Failure::NotFound));
        assert_eq!(WinCred.delete(&target), Err(Failure::NotFound));
    }

    #[test]
    fn list_returns_the_targets_under_a_prefix_with_their_usernames() {
        let first = target("list:a");
        let second = target("list:b");
        let outside = target("listed-elsewhere");
        WinCred.write(&first, "", b"1").unwrap();
        WinCred.write(&second, "octo", b"2").unwrap();
        WinCred.write(&outside, "", b"3").unwrap();
        let mut listed = WinCred.list(&target("list:")).unwrap();
        for written in [&first, &second, &outside] {
            WinCred.delete(written).unwrap();
        }
        listed.sort_by(|a, b| a.target.cmp(&b.target));
        assert_eq!(
            listed,
            vec![
                Credential {
                    target: first,
                    username: String::new()
                },
                Credential {
                    target: second,
                    username: "octo".into()
                },
            ]
        );
    }

    /// A target in which `service=` or `target=` follows the first colon reads back but is never
    /// listed, so a scheme that needs its credentials listed must not name them that way.
    #[test]
    fn a_target_with_a_keyword_after_its_first_colon_is_left_out_of_listings() {
        let prefix = format!("credrelay-test-{}:", std::process::id());
        let hidden = format!("{prefix}service=x");
        let listed = format!("{prefix}username=x");
        WinCred.write(&hidden, "", b"1").unwrap();
        WinCred.write(&listed, "", b"2").unwrap();
        let found = WinCred.list(&prefix).unwrap();
        let read = WinCred.read(&hidden);
        WinCred.delete(&hidden).unwrap();
        WinCred.delete(&listed).unwrap();
        assert_eq!(read.unwrap(), b"1");
        assert_eq!(
            found,
            vec![Credential {
                target: listed,
                username: String::new()
            }]
        );
    }

    #[test]
    fn list_of_an_unused_prefix_is_empty() {
        assert_eq!(WinCred.list(&target("nothing-here:")).unwrap(), Vec::new());
    }
}
