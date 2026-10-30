use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    about = "credrelay Windows side: answers credential requests on stdio from the Windows Credential Manager.\n\nNot meant to be run directly by an end user: credrelay-client spawns it, passes every flag below, and speaks JSON lines over its stdin/stdout. Which credentials may be touched is decided there."
)]
// Every flag is required, with no default: credrelay-client passes them all.
pub struct Config {
    /// What to log, in `RUST_LOG` syntax, e.g. `info`. A flag rather than `RUST_LOG` itself, since
    /// environment variables set in WSL don't reach a Windows process started from it.
    #[arg(long)]
    pub log_filter: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_filter_is_required() {
        assert!(Config::try_parse_from(["credrelay-server"]).is_err());
        let config = Config::try_parse_from(["credrelay-server", "--log-filter", "debug"]).unwrap();
        assert_eq!(config.log_filter, "debug");
    }
}
