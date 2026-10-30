use crate::{Allowlist, CredentialStore, Failure, Reply, Request, Response};

/// Answers one request from `store`, refusing anything outside `allowlist` before the store sees it.
pub fn handle(store: &impl CredentialStore, allowlist: &Allowlist, request: Request) -> Response {
    // A listed prefix inside an allowed one can only match allowed targets.
    let scope = match &request {
        Request::Read { target } | Request::Write { target, .. } | Request::Delete { target } => {
            target
        }
        Request::List { prefix } => prefix,
    };
    if !allowlist.allows(scope) {
        return Err(Failure::Denied);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Credential, MemoryStore};

    fn allowlist() -> Allowlist {
        Allowlist::new(vec!["gh:".into()]).unwrap()
    }

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
    fn a_written_secret_reads_back() {
        let store = MemoryStore::default();
        assert_eq!(
            handle(&store, &allowlist(), write("gh:github.com:", "", b"t0ken")),
            Ok(Reply::Done)
        );
        assert_eq!(
            handle(&store, &allowlist(), read("gh:github.com:")),
            Ok(Reply::Secret(b"t0ken".to_vec()))
        );
    }

    #[test]
    fn a_missing_credential_is_not_found() {
        let store = MemoryStore::default();
        assert_eq!(
            handle(&store, &allowlist(), read("gh:github.com:")),
            Err(Failure::NotFound)
        );
    }

    #[test]
    fn a_deleted_credential_is_gone() {
        let store = MemoryStore::default();
        handle(&store, &allowlist(), write("gh:github.com:", "", b"t0ken")).unwrap();
        let delete = Request::Delete {
            target: "gh:github.com:".into(),
        };
        assert_eq!(
            handle(&store, &allowlist(), delete.clone()),
            Ok(Reply::Done)
        );
        assert_eq!(handle(&store, &allowlist(), delete), Err(Failure::NotFound));
    }

    #[test]
    fn list_returns_only_targets_under_the_prefix() {
        let store = MemoryStore::default();
        handle(&store, &allowlist(), write("gh:github.com:", "", b"a")).unwrap();
        handle(
            &store,
            &allowlist(),
            write("gh:github.com:octo", "octo", b"b"),
        )
        .unwrap();
        handle(&store, &allowlist(), write("gh:example.com:", "", b"c")).unwrap();
        let mut listed = match handle(
            &store,
            &allowlist(),
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

    #[test]
    fn every_operation_outside_the_allowlist_is_denied_without_touching_the_store() {
        let store = MemoryStore::default();
        store
            .write("git:https://github.com", "octo", b"secret")
            .unwrap();
        let outside = [
            read("git:https://github.com"),
            write("git:https://github.com", "octo", b"overwritten"),
            Request::Delete {
                target: "git:https://github.com".into(),
            },
            Request::List {
                prefix: "git:".into(),
            },
            Request::List {
                prefix: String::new(),
            },
        ];
        for request in outside {
            assert_eq!(
                handle(&store, &allowlist(), request.clone()),
                Err(Failure::Denied),
                "{request:?}"
            );
        }
        assert_eq!(store.read("git:https://github.com").unwrap(), b"secret");
    }
}
