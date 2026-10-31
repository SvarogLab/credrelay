use crate::{CredentialStore, DecodeError, Reply, Request, Response, decode_line, encode_line};

/// Answers one request from `store`.
pub fn handle(store: &impl CredentialStore, request: Request) -> Response {
    match request {
        Request::Read { target } => store.read(&target).map(Reply::Secret),
        Request::Write {
            target,
            username,
            secret,
        } => store
            .write(&target, &username, &secret)
            .map(|()| Reply::Done),
        Request::Delete { target } => store.delete(&target).map(|()| Reply::Done),
        Request::List { prefix } => store.list(&prefix).map(Reply::Credentials),
    }
}

/// Answers one request line with one answer line, newline included. A line that isn't a request
/// gets no answer: the client never sends one.
pub fn answer(store: &impl CredentialStore, line: &str) -> Result<String, DecodeError> {
    let request: Request = decode_line(line)?;
    Ok(encode_line(&handle(store, request)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credential, Failure, MemoryStore};

    fn write(target: &str, username: &str, secret: &[u8]) -> Request {
        Request::Write {
            target: target.into(),
            username: username.into(),
            secret: secret.to_vec(),
        }
    }

    fn read(target: &str) -> Request {
        Request::Read {
            target: target.into(),
        }
    }

    #[test]
    fn a_request_line_gets_its_answer_line() {
        let store = MemoryStore::default();
        let line = answer(&store, r#"{"op":"read","target":"gh:github.com:"}"#).unwrap();
        assert_eq!(line, "{\"Err\":\"not_found\"}\n");
        assert!(answer(&store, "not json").is_err());
    }

    #[test]
    fn a_written_secret_reads_back() {
        let store = MemoryStore::default();
        assert_eq!(
            handle(&store, write("gh:github.com:", "", b"t0ken")),
            Ok(Reply::Done)
        );
        assert_eq!(
            handle(&store, read("gh:github.com:")),
            Ok(Reply::Secret(b"t0ken".to_vec()))
        );
    }

    #[test]
    fn a_missing_credential_is_not_found() {
        let store = MemoryStore::default();
        assert_eq!(
            handle(&store, read("gh:github.com:")),
            Err(Failure::NotFound)
        );
    }

    #[test]
    fn a_deleted_credential_is_gone() {
        let store = MemoryStore::default();
        handle(&store, write("gh:github.com:", "", b"t0ken")).unwrap();
        let delete = Request::Delete {
            target: "gh:github.com:".into(),
        };
        assert_eq!(handle(&store, delete.clone()), Ok(Reply::Done));
        assert_eq!(handle(&store, delete), Err(Failure::NotFound));
    }

    #[test]
    fn list_returns_only_targets_under_the_prefix() {
        let store = MemoryStore::default();
        handle(&store, write("gh:github.com:", "", b"a")).unwrap();
        handle(&store, write("gh:github.com:octo", "octo", b"b")).unwrap();
        handle(&store, write("gh:example.com:", "", b"c")).unwrap();
        let mut listed = match handle(
            &store,
            Request::List {
                prefix: "gh:github.com:".into(),
            },
        ) {
            Ok(Reply::Credentials(listed)) => listed,
            other => panic!("expected credentials, got {other:?}"),
        };
        listed.sort_by(|a, b| a.target.cmp(&b.target));
        assert_eq!(
            listed,
            vec![
                Credential {
                    target: "gh:github.com:".into(),
                    username: String::new()
                },
                Credential {
                    target: "gh:github.com:octo".into(),
                    username: "octo".into()
                },
            ]
        );
    }
}
