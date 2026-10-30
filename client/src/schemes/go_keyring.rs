//! `zalando/go-keyring`, which gh and glab use: attributes `{service, username}` on Linux, a generic
//! credential `service:username` holding the secret's bytes as they are on Windows.
//!
//! Other libraries store the same two attributes under other Windows names, so the attributes
//! alone don't say an item is go-keyring's. The service does: each application names its own,
//! and the services listed in the scheme's prefixes are the ones known to use go-keyring.

use credrelay_protocol::Credential;

use credrelay_wincred::go_keyring_target;

use super::{Attributes, Scheme};
use crate::schemes::Prefixes;

const SERVICE: &str = "service";
const USERNAME: &str = "username";

pub struct GoKeyring {
    prefixes: Prefixes,
}

impl GoKeyring {
    pub fn new(prefixes: Prefixes) -> Self {
        Self { prefixes }
    }
}

impl Scheme for GoKeyring {
    fn prefixes(&self) -> &Prefixes {
        &self.prefixes
    }

    fn credential(&self, attributes: &Attributes) -> Option<Credential> {
        if attributes.len() != 2 {
            return None;
        }
        let service = attributes.get(SERVICE)?;
        let username = attributes.get(USERNAME)?;
        if !self.prefixes.covers(service) {
            return None;
        }
        Some(Credential {
            target: go_keyring_target(service, username),
            username: username.clone(),
        })
    }

    fn search_prefix(&self, attributes: &Attributes) -> Option<String> {
        attributes.get(SERVICE).map(|service| format!("{service}:"))
    }

    fn attributes(&self, credential: &Credential) -> Option<Attributes> {
        // go-keyring stores the username on its own too, which is what tells apart where the
        // service ends in a target that may hold colons on either side.
        let service = credential
            .target
            .strip_suffix(credential.username.as_str())?
            .strip_suffix(':')?;
        if !self.prefixes.covers(service) {
            return None;
        }
        Some(Attributes::from([
            (SERVICE.to_owned(), service.to_owned()),
            (USERNAME.to_owned(), credential.username.clone()),
        ]))
    }
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

    fn scheme() -> GoKeyring {
        GoKeyring::new(Prefixes::new(vec!["gh:".into(), "glab:".into()]).unwrap())
    }

    fn credential(target: &str, username: &str) -> Credential {
        Credential {
            target: target.into(),
            username: username.into(),
        }
    }

    /// Target names as go-keyring writes them on Windows, for gh's active account, gh's
    /// per-user entry and glab's token.
    #[test]
    fn stores_service_and_username_as_go_keyring_names_them() {
        let cases = [
            ("gh:github.com", "", "gh:github.com:"),
            ("gh:github.com", "octo", "gh:github.com:octo"),
            ("glab:gitlab.com:token", "", "glab:gitlab.com:token:"),
        ];
        for (service, username, target) in cases {
            let attributes = attributes(&[("service", service), ("username", username)]);
            assert_eq!(
                scheme().credential(&attributes),
                Some(credential(target, username))
            );
            assert_eq!(
                scheme().attributes(&credential(target, username)),
                Some(attributes)
            );
        }
    }

    #[test]
    fn stores_nothing_but_exactly_service_and_username() {
        for pairs in [
            &[("service", "gh:github.com")][..],
            &[("username", "octo")],
            &[
                ("service", "gh:github.com"),
                ("username", "octo"),
                ("application", "other"),
            ],
        ] {
            assert_eq!(scheme().credential(&attributes(pairs)), None, "{pairs:?}");
        }
    }

    #[test]
    fn claims_only_the_services_under_its_prefixes() {
        let other = attributes(&[("service", "git"), ("username", "https://github.com")]);
        assert_eq!(scheme().credential(&other), None);
        assert_eq!(
            scheme().attributes(&credential("git:https://github.com", "https://github.com")),
            None
        );
    }

    #[test]
    fn a_credential_whose_target_doesnt_end_in_its_username_isnt_go_keyrings() {
        assert_eq!(
            scheme().attributes(&credential("octo.gh:github.com", "octo")),
            None
        );
    }

    #[test]
    fn a_credential_named_only_by_a_prefix_isnt_go_keyrings() {
        assert_eq!(scheme().attributes(&credential("gh:", "")), None);
    }

    #[test]
    fn a_search_by_service_lists_only_that_services_targets() {
        assert_eq!(
            scheme().search_prefix(&attributes(&[("service", "gh:github.com")])),
            Some("gh:github.com:".into())
        );
        assert_eq!(
            scheme().search_prefix(&attributes(&[("username", "octo")])),
            None
        );
    }
}
