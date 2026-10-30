/// The target prefixes the server may touch. Every other credential in the Credential Manager stays
/// out of reach of WSL, whichever process there asks.
#[derive(Debug, Clone)]
pub struct Allowlist {
    prefixes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AllowlistError {
    #[error("at least one target prefix must be allowed")]
    Empty,
    #[error("an empty prefix would allow every credential")]
    EmptyPrefix,
}

impl Allowlist {
    pub fn new(prefixes: Vec<String>) -> Result<Self, AllowlistError> {
        if prefixes.is_empty() {
            return Err(AllowlistError::Empty);
        }
        if prefixes.iter().any(String::is_empty) {
            return Err(AllowlistError::EmptyPrefix);
        }
        Ok(Self { prefixes })
    }

    pub fn allows(&self, target: &str) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| target.starts_with(prefix.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowlist(prefixes: &[&str]) -> Allowlist {
        Allowlist::new(prefixes.iter().map(|p| p.to_string()).collect()).unwrap()
    }

    #[test]
    fn allows_a_target_under_any_listed_prefix() {
        let allowlist = allowlist(&["gh:", "glab:"]);
        assert!(allowlist.allows("gh:github.com:"));
        assert!(allowlist.allows("glab:gitlab.com:token:"));
    }

    #[test]
    fn denies_a_target_outside_every_prefix() {
        let allowlist = allowlist(&["gh:", "glab:"]);
        assert!(!allowlist.allows("git:https://github.com"));
        assert!(!allowlist.allows("gh"));
        assert!(!allowlist.allows(""));
    }

    #[test]
    fn refuses_to_allow_nothing_or_everything() {
        assert_eq!(Allowlist::new(vec![]).unwrap_err(), AllowlistError::Empty);
        assert_eq!(
            Allowlist::new(vec!["gh:".into(), String::new()]).unwrap_err(),
            AllowlistError::EmptyPrefix
        );
    }
}
