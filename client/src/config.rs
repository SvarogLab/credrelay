use std::path::PathBuf;

use clap::Parser;
use librelay::client::log::LogFilter;

use crate::schemes::Prefixes;

/// Every flag has a default: run bare, this is the service gh, glab and credrelay-keyring need.
#[derive(Parser, Debug)]
#[command(
    about = "credrelay WSL side: serves the freedesktop Secret Service on the session bus, from the Windows Credential Manager."
)]
pub struct Config {
    /// The `credrelay-server.exe` to start, searched for on `PATH` unless it is a path.
    #[arg(long, default_value = "credrelay-server.exe")]
    pub server_exe: PathBuf,

    /// A service prefix known to belong to an application on zalando/go-keyring, whose items are
    /// therefore stored where its Windows build looks for them: gh, glab, and the services
    /// credrelay-keyring is documented with. Repeat it for each prefix; every other item is stored
    /// under credrelay's own names.
    #[arg(
        long = "go-keyring-prefix",
        default_values = ["gh:", "glab:", "age:", "bao:", "kubectl:"],
        value_parser = non_empty
    )]
    go_keyring_prefix: Vec<String>,

    /// How long credrelay-server may take to answer one request, in seconds. A request it doesn't
    /// answer in time fails; the others, each on a stream of its own, carry on.
    #[arg(long, default_value_t = 10)]
    pub request_timeout_secs: u64,
}

impl Config {
    pub fn go_keyring_prefixes(&self) -> Prefixes {
        Prefixes::new(self.go_keyring_prefix.clone())
            .expect("clap keeps at least one prefix, none of them empty")
    }

    /// The arguments credrelay-server is started with.
    pub fn server_args(&self, filter: &LogFilter) -> Vec<String> {
        filter.server_args().to_vec()
    }
}

fn non_empty(prefix: &str) -> Result<String, String> {
    if prefix.is_empty() {
        Err("an empty prefix would claim every service".into())
    } else {
        Ok(prefix.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_it_serves_gh_glab_and_credrelay_keyrings_services_through_the_server_on_path() {
        let config = Config::try_parse_from(["credrelay-client"]).unwrap();
        assert_eq!(config.server_exe, PathBuf::from("credrelay-server.exe"));
        assert_eq!(config.request_timeout_secs, 10);
        assert_eq!(
            config.go_keyring_prefix,
            ["gh:", "glab:", "age:", "bao:", "kubectl:"]
        );
    }

    #[test]
    fn an_empty_go_keyring_prefix_is_refused_while_parsing() {
        let parsed = Config::try_parse_from(["credrelay-client", "--go-keyring-prefix", ""]);
        assert!(parsed.is_err());
    }

    #[test]
    fn the_go_keyring_prefixes_come_out_ready_for_the_scheme() {
        let config =
            Config::try_parse_from(["credrelay-client", "--go-keyring-prefix", "gh:"]).unwrap();
        assert!(config.go_keyring_prefixes().covers("gh:github.com"));
        assert!(!config.go_keyring_prefixes().covers("glab:gitlab.com"));
    }

    #[test]
    fn listed_go_keyring_prefixes_replace_the_defaults() {
        let config = Config::try_parse_from([
            "credrelay-client",
            "--go-keyring-prefix",
            "gh:",
            "--go-keyring-prefix",
            "bao:",
        ])
        .unwrap();
        assert_eq!(config.go_keyring_prefix, ["gh:", "bao:"]);
    }
}
