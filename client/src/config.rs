use std::path::PathBuf;

use clap::Parser;

/// Every flag has a default: run bare, this is the service gh and glab need.
#[derive(Parser, Debug)]
#[command(
    about = "credrelay WSL side: serves the freedesktop Secret Service on the session bus, from the Windows Credential Manager."
)]
pub struct Config {
    /// The `credrelay-server.exe` to start, searched for on `PATH` unless it is a path.
    #[arg(long, default_value = "credrelay-server.exe")]
    pub server_exe: PathBuf,

    /// A service prefix known to belong to an application on zalando/go-keyring, whose items are
    /// therefore stored where its Windows build looks for them. Repeat it for each prefix; every
    /// other item is stored under credrelay's own names.
    #[arg(long = "go-keyring-prefix", default_values = ["gh:", "glab:"])]
    pub go_keyring_prefixes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_it_serves_gh_and_glab_through_the_server_on_path() {
        let config = Config::try_parse_from(["credrelay-client"]).unwrap();
        assert_eq!(config.server_exe, PathBuf::from("credrelay-server.exe"));
        assert_eq!(config.go_keyring_prefixes, ["gh:", "glab:"]);
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
