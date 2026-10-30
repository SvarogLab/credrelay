use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    about = "credrelay Windows side: answers credential requests on stdio from the Windows Credential Manager.\n\nNot meant to be run directly by an end user: credrelay-client spawns it and speaks JSON lines over its stdin/stdout. Which credentials may be touched is decided there."
)]
pub struct Config {}
