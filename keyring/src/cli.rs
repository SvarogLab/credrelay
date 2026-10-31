//! `credrelay-keyring`'s commands.

use clap::{Parser, Subcommand};

use crate::backend::{Backend, BackendError};
use crate::kube::{self, KubeError};

#[derive(Parser, Debug)]
#[command(
    about = "Reads and writes secrets the way zalando/go-keyring keeps them: an item {service, username} in the Secret Service on Linux, the generic credential service:username in the Credential Manager on Windows."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Writes the secret to stdout, exactly as stored.
    Get(Key),
    /// Stores stdin as the secret, exactly as read, replacing any secret there.
    Set(Key),
    /// Deletes the secret.
    Delete(Key),
    /// Writes a kubectl `ExecCredential` for the stored kubeconfig user entry; see the README.
    KubeCredential(Key),
}

#[derive(clap::Args, Debug)]
pub struct Key {
    pub service: String,
    #[arg(long, default_value = "")]
    pub username: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("no secret for service {service:?}, username {username:?}")]
    NotFound { service: String, username: String },
    #[error(transparent)]
    Backend(#[from] BackendError),
    #[error(transparent)]
    Kube(#[from] KubeError),
}

/// Runs `command` with `input` as stdin, returning what to write to stdout.
pub async fn run(
    backend: &impl Backend,
    command: &Command,
    input: &[u8],
) -> Result<Vec<u8>, CliError> {
    match command {
        Command::Get(key) => get(backend, key).await,
        Command::Set(key) => {
            backend.set(&key.service, &key.username, input).await?;
            Ok(Vec::new())
        }
        Command::Delete(key) => {
            if backend.delete(&key.service, &key.username).await? {
                Ok(Vec::new())
            } else {
                Err(not_found(key))
            }
        }
        Command::KubeCredential(key) => {
            let stored = get(backend, key).await?;
            Ok(kube::exec_credential(&stored)?.into_bytes())
        }
    }
}

async fn get(backend: &impl Backend, key: &Key) -> Result<Vec<u8>, CliError> {
    backend
        .get(&key.service, &key.username)
        .await?
        .ok_or_else(|| not_found(key))
}

fn not_found(key: &Key) -> CliError {
    CliError::NotFound {
        service: key.service.clone(),
        username: key.username.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::memory::Memory;

    fn parse(args: &[&str]) -> Command {
        Cli::try_parse_from([&["credrelay-keyring"], args].concat())
            .unwrap()
            .command
    }

    #[tokio::test]
    async fn set_stores_stdin_exactly_and_get_returns_it() {
        let backend = Memory::default();
        let key = "# created: 2026-01-01\nAGE-SECRET-KEY-1\n";
        run(&backend, &parse(&["set", "age:default"]), key.as_bytes())
            .await
            .unwrap();
        assert_eq!(
            run(&backend, &parse(&["get", "age:default"]), b"")
                .await
                .unwrap(),
            key.as_bytes()
        );
        assert_eq!(
            backend.get("age:default", "").await.unwrap(),
            Some(key.as_bytes().to_vec())
        );
    }

    #[tokio::test]
    async fn the_username_is_part_of_the_key() {
        let backend = Memory::default();
        run(
            &backend,
            &parse(&["set", "gh:github.com", "--username", "octo"]),
            b"t",
        )
        .await
        .unwrap();
        assert_eq!(
            backend.get("gh:github.com", "octo").await.unwrap(),
            Some(b"t".to_vec())
        );
        assert!(matches!(
            run(&backend, &parse(&["get", "gh:github.com"]), b"").await,
            Err(CliError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn a_missing_secret_is_an_error_to_get_and_to_delete() {
        let backend = Memory::default();
        for command in [&["get", "age:default"][..], &["delete", "age:default"]] {
            assert!(matches!(
                run(&backend, &parse(command), b"").await,
                Err(CliError::NotFound { .. })
            ));
        }
    }

    #[tokio::test]
    async fn delete_removes_the_secret() {
        let backend = Memory::default();
        run(&backend, &parse(&["set", "age:default"]), b"k")
            .await
            .unwrap();
        run(&backend, &parse(&["delete", "age:default"]), b"")
            .await
            .unwrap();
        assert_eq!(backend.get("age:default", "").await.unwrap(), None);
    }

    #[tokio::test]
    async fn kube_credential_turns_the_stored_user_entry_into_an_exec_credential() {
        let backend = Memory::default();
        run(
            &backend,
            &parse(&["set", "kubectl:admin@main"]),
            br#"{"token":"t0ken"}"#,
        )
        .await
        .unwrap();
        let output = run(
            &backend,
            &parse(&["kube-credential", "kubectl:admin@main"]),
            b"",
        )
        .await
        .unwrap();
        assert_eq!(
            output,
            kube::exec_credential(br#"{"token":"t0ken"}"#)
                .unwrap()
                .as_bytes()
        );
    }
}
