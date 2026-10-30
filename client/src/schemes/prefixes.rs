/// Target prefixes a scheme stores credentials under. Nothing outside them is touched, so an
/// application can't overwrite or delete another one's Windows credential by accident.
#[derive(Debug, Clone)]
pub struct Prefixes {
    prefixes: Vec<String>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PrefixesError {
    #[error("at least one target prefix is needed")]
    Empty,
    #[error("an empty prefix would cover every credential")]
    EmptyPrefix,
}

impl Prefixes {
    pub fn new(prefixes: Vec<String>) -> Result<Self, PrefixesError> {
        if prefixes.is_empty() {
            return Err(PrefixesError::Empty);
        }
        if prefixes.iter().any(String::is_empty) {
            return Err(PrefixesError::EmptyPrefix);
        }
        Ok(Self { prefixes })
    }

    pub fn as_slice(&self) -> &[String] {
        &self.prefixes
    }

    pub fn covers(&self, target: &str) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| target.starts_with(prefix.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefixes(prefixes: &[&str]) -> Prefixes {
        Prefixes::new(prefixes.iter().map(|p| p.to_string()).collect()).unwrap()
    }

    #[test]
    fn covers_a_target_under_any_listed_prefix() {
        let prefixes = prefixes(&["gh:", "glab:"]);
        assert!(prefixes.covers("gh:github.com:"));
        assert!(prefixes.covers("glab:gitlab.com:token:"));
    }

    #[test]
    fn doesnt_cover_a_target_outside_every_prefix() {
        let prefixes = prefixes(&["gh:", "glab:"]);
        assert!(!prefixes.covers("git:https://github.com"));
        assert!(!prefixes.covers("gh"));
        assert!(!prefixes.covers(""));
    }

    #[test]
    fn refuses_to_cover_nothing_or_everything() {
        assert_eq!(Prefixes::new(vec![]).unwrap_err(), PrefixesError::Empty);
        assert_eq!(
            Prefixes::new(vec!["gh:".into(), String::new()]).unwrap_err(),
            PrefixesError::EmptyPrefix
        );
    }
}
