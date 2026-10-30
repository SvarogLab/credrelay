use clap::Parser;
use librelay::server::log::LogArgs;

#[derive(Parser, Debug)]
#[command(
    about = "credrelay Windows side: answers credential requests on stdio from the Windows Credential Manager.\n\nNot meant to be run directly by an end user: credrelay-client spawns it, passes every flag below, and speaks JSON lines over its stdin/stdout. Which credentials may be touched is decided there."
)]
// Every flag is required, with no default: credrelay-client passes them all.
pub struct Config {
    #[command(flatten)]
    pub log: LogArgs,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_log_filter_is_required() {
        assert!(Config::try_parse_from(["credrelay-server"]).is_err());
        let config = Config::try_parse_from(["credrelay-server", "--log-filter", "debug"]).unwrap();
        assert_eq!(config.log.log_filter, "debug");
    }
}
