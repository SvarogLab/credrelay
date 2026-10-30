use clap::Parser;

/// Every flag is required, with no default and no environment fallback: this process is spawned
/// by `credrelay-client`, which passes them all, and a guessed allowlist is a security decision
/// nobody made.
#[derive(Parser, Debug)]
#[command(
    about = "credrelay Windows side: answers credential requests on stdio from the Windows Credential Manager.\n\nNot meant to be run directly by an end user: credrelay-client spawns it, passes every flag below, and speaks JSON lines over its stdin/stdout."
)]
pub struct Config {
    /// A target prefix this process may read, write, delete and list under, e.g. `gh:`. Repeat it
    /// for each prefix; every other generic credential stays out of reach.
    #[arg(long = "allow-prefix", required = true)]
    pub allow_prefixes: Vec<String>,
}
