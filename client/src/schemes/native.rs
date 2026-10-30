//! credrelay's own convention, for items no other scheme claims: only Linux applications see them.
//! The target is the item's attributes after a prefix of its own, sorted, each pair written
//! `key,value` and the pairs joined by `;`, so the same attributes always land in the same
//! credential, and listing the prefix yields every item's attributes without reading a secret.
//!
//! Keys and values are percent-encoded down to unreserved characters. Besides keeping the
//! separators unambiguous, that leaves no `=` or `:` after the prefix: the Credential Manager
//! leaves a target out of listings when `service=` or `target=` follows its first colon.

use credrelay_protocol::Credential;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};

use super::{Attributes, Scheme};
use crate::schemes::Prefixes;

const PREFIX: &str = "credrelay:";
const PAIRS: char = ';';
const KEY_VALUE: char = ',';
const RESERVED: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub struct Native {
    prefixes: Prefixes,
}

impl Default for Native {
    fn default() -> Self {
        Self {
            prefixes: Prefixes::new(vec![PREFIX.into()]).expect("one non-empty prefix"),
        }
    }
}

impl Scheme for Native {
    fn prefixes(&self) -> &Prefixes {
        &self.prefixes
    }

    fn credential(&self, attributes: &Attributes) -> Option<Credential> {
        let encoded = attributes
            .iter()
            .map(|(key, value)| format!("{}{KEY_VALUE}{}", encode(key), encode(value)))
            .collect::<Vec<_>>()
            .join(&PAIRS.to_string());
        Some(Credential {
            target: format!("{PREFIX}{encoded}"),
            username: String::new(),
        })
    }

    fn search_prefix(&self, _attributes: &Attributes) -> Option<String> {
        None
    }

    fn attributes(&self, credential: &Credential) -> Option<Attributes> {
        let encoded = credential.target.strip_prefix(PREFIX)?;
        if encoded.is_empty() {
            return Some(Attributes::new());
        }
        encoded
            .split(PAIRS)
            .map(|pair| {
                let (key, value) = pair.split_once(KEY_VALUE)?;
                Some((decode(key)?, decode(value)?))
            })
            .collect()
    }
}

fn encode(text: &str) -> String {
    utf8_percent_encode(text, RESERVED).to_string()
}

fn decode(text: &str) -> Option<String> {
    percent_decode_str(text)
        .decode_utf8()
        .ok()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attributes(pairs: &[(&str, &str)]) -> Attributes {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn claims_any_attributes_and_reads_them_back_from_the_target() {
        for pairs in [
            &[][..],
            &[("service", "git"), ("username", "https://github.com")],
            &[
                ("xdg:schema", "org.freedesktop.Secret.Generic"),
                ("a&b", "c=d"),
                ("unicode", "mot de passe ✓"),
                ("empty", ""),
            ],
        ] {
            let attributes = attributes(pairs);
            let credential = Native::default().credential(&attributes).unwrap();
            assert!(credential.target.starts_with(PREFIX), "{credential:?}");
            assert_eq!(Native::default().attributes(&credential), Some(attributes));
        }
    }

    #[test]
    fn the_same_attributes_always_name_the_same_target() {
        let one = attributes(&[("service", "git"), ("username", "octo")]);
        let target = Native::default().credential(&one).unwrap().target;
        assert_eq!(target, "credrelay:service,git;username,octo");
    }

    /// The Credential Manager leaves `…:service=…` out of listings, so no `=` or `:` may appear
    /// in what follows the prefix, whatever the attributes hold.
    #[test]
    fn a_target_holds_no_equals_sign_or_colon_after_the_prefix() {
        let attributes = attributes(&[("service", "a=b:c"), ("target", "https://x/?y=z")]);
        let target = Native::default().credential(&attributes).unwrap().target;
        let encoded = target.strip_prefix(PREFIX).unwrap();
        assert!(!encoded.contains(['=', ':']), "{target}");
    }

    #[test]
    fn a_malformed_target_under_the_prefix_isnt_its() {
        for target in ["credrelay:no-separator", "credrelay:a,%FF"] {
            let credential = Credential {
                target: target.into(),
                username: String::new(),
            };
            assert_eq!(Native::default().attributes(&credential), None, "{target}");
        }
    }

    #[test]
    fn a_credential_outside_its_prefix_isnt_its() {
        let credential = Credential {
            target: "gh:github.com:".into(),
            username: String::new(),
        };
        assert_eq!(Native::default().attributes(&credential), None);
    }
}
