use std::path::PathBuf;

use clap::Parser;

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
        default_values = ["gh:", "glab:", "age:", "bao:", "kubectl:"]
    )]
    pub go_keyring_prefixes: Vec<String>,

    /// How long credrelay-server may take to answer one request, in seconds. A request it doesn't
    /// answer in time fails; the others, each on a stream of its own, carry on.
    #[arg(long, default_value_t = 10)]
    pub request_timeout_secs: u64,
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
            config.go_keyring_prefixes,
            ["gh:", "glab:", "age:", "bao:", "kubectl:"]
        );
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
        assert_eq!(config.go_keyring_prefixes, ["gh:", "bao:"]);
    }
}
