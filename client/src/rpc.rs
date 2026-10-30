use credrelay_protocol::{Credential, Failure, Reply, Request, Response, decode_line, encode_line};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Failed(#[from] Failure),
    #[error("lost the link to credrelay-server: {0}")]
    Link(String),
}

/// The client's end of the server's stdio. Requests go one at a time: the protocol carries no
/// request ids, so an answer belongs to whichever request is in flight.
pub struct Rpc {
    link: Mutex<Link>,
}

struct Link {
    reader: BufReader<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
}

impl Rpc {
    pub fn new(
        reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
    ) -> Self {
        Self {
            link: Mutex::new(Link {
                reader: BufReader::new(Box::new(reader)),
                writer: Box::new(writer),
            }),
        }
    }

    pub async fn read(&self, target: &str) -> Result<Vec<u8>, RpcError> {
        let target = target.to_owned();
        match self.call(Request::Read { target }).await? {
            Reply::Secret(secret) => Ok(secret),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn write(&self, target: &str, username: &str, secret: &[u8]) -> Result<(), RpcError> {
        let request = Request::Write {
            target: target.to_owned(),
            username: username.to_owned(),
            secret: secret.to_vec(),
        };
        match self.call(request).await? {
            Reply::Done => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn delete(&self, target: &str) -> Result<(), RpcError> {
        let target = target.to_owned();
        match self.call(Request::Delete { target }).await? {
            Reply::Done => Ok(()),
            other => Err(unexpected(&other)),
        }
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<Credential>, RpcError> {
        let prefix = prefix.to_owned();
        match self.call(Request::List { prefix }).await? {
            Reply::Credentials(credentials) => Ok(credentials),
            other => Err(unexpected(&other)),
        }
    }

    async fn call(&self, request: Request) -> Result<Reply, RpcError> {
        let mut link = self.link.lock().await;
        let link = &mut *link;
        let lost = |error: std::io::Error| RpcError::Link(error.to_string());
        link.writer
            .write_all(encode_line(&request).as_bytes())
            .await
            .map_err(lost)?;
        link.writer.flush().await.map_err(lost)?;
        let mut line = String::new();
        if link.reader.read_line(&mut line).await.map_err(lost)? == 0 {
            return Err(RpcError::Link("the server closed its output".into()));
        }
        let response: Response =
            decode_line(&line).map_err(|error| RpcError::Link(error.to_string()))?;
        Ok(response?)
    }
}

fn unexpected(reply: &Reply) -> RpcError {
    RpcError::Link(format!("answer out of step with the request: {reply:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::in_memory;

    #[tokio::test]
    async fn every_operation_reaches_the_store() {
        let rpc = in_memory();
        rpc.write("gh:github.com:octo", "octo", b"t0ken")
            .await
            .unwrap();
        assert_eq!(rpc.read("gh:github.com:octo").await.unwrap(), b"t0ken");
        assert_eq!(
            rpc.list("gh:").await.unwrap(),
            vec![Credential {
                target: "gh:github.com:octo".into(),
                username: "octo".into()
            }]
        );
        rpc.delete("gh:github.com:octo").await.unwrap();
        assert!(matches!(
            rpc.read("gh:github.com:octo").await,
            Err(RpcError::Failed(Failure::NotFound))
        ));
    }

    #[tokio::test]
    async fn concurrent_requests_each_get_their_own_answer() {
        let rpc = std::sync::Arc::new(in_memory());
        let writes = (0..32).map(|i| {
            let rpc = rpc.clone();
            tokio::spawn(async move {
                let target = format!("gh:host{i}:");
                rpc.write(&target, "", i.to_string().as_bytes())
                    .await
                    .unwrap();
                assert_eq!(rpc.read(&target).await.unwrap(), i.to_string().as_bytes());
            })
        });
        for write in writes {
            write.await.unwrap();
        }
    }

    #[tokio::test]
    async fn a_closed_link_is_a_link_error() {
        let (client, server) = tokio::io::duplex(1024);
        drop(server);
        let (reader, writer) = tokio::io::split(client);
        let rpc = Rpc::new(reader, writer);
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
    }

    #[tokio::test]
    async fn an_answer_of_the_wrong_kind_is_a_link_error() {
        let (client, server) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client);
        let rpc = Rpc::new(reader, writer);
        tokio::spawn(async move {
            let (server_reader, mut server_writer) = tokio::io::split(server);
            let mut lines = BufReader::new(server_reader).lines();
            while let Ok(Some(_)) = lines.next_line().await {
                let response: Response = Ok(Reply::Done);
                server_writer
                    .write_all(encode_line(&response).as_bytes())
                    .await
                    .unwrap();
            }
        });
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
    }
}
