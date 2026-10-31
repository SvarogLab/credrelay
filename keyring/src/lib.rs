//! go-keyring's convention from the command line, on Linux and on Windows alike: an item
//! `{service, username}` in the Secret Service, or the generic credential `service:username` in the
//! Credential Manager. A secret one side stores, the other reads.

pub mod backend;
pub mod bao;
pub mod cli;
pub mod kube;

use std::fmt::Display;
use std::io::Write;
use std::process::ExitCode;

/// Ends a command run as `program`: its output to stdout and success, or its error to stderr
/// behind the program's name and failure.
pub fn finish(program: &str, result: Result<Vec<u8>, impl Display>) -> ExitCode {
    let written = match result {
        Ok(output) => std::io::stdout().write_all(&output),
        Err(error) => {
            eprintln!("{program}: {error}");
            return ExitCode::FAILURE;
        }
    };
    match written {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{program}: can't write to stdout: {error}");
            ExitCode::FAILURE
        }
    }
}
