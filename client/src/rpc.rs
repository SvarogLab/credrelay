//! Requests to credrelay-server, one stream each: the client opens a stream, writes one request
//! line, and reads one answer line back. Streams are independent, so a slow request holds up no
//! other, and a request that times out or is abandoned leaves the rest untouched.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use credrelay_protocol::{Credential, Failure, Reply, Request, Response, decode_line, encode_line};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Failed(#[from] Failure),
    #[error("lost the link to credrelay-server: {0}")]
    Link(String),
}

/// A stream to the server, one per request.
pub trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

type Opening = Pin<Box<dyn Future<Output = io::Result<Box<dyn Stream>>> + Send>>;

#[derive(Clone)]
pub struct Rpc {
    open: Arc<dyn Fn() -> Opening + Send + Sync>,
    timeout: Duration,
}

impl Rpc {
    /// Sends each request over a stream from `open`, giving the server `timeout` to answer it.
    pub fn new<F, S>(open: impl Fn() -> F + Send + Sync + 'static, timeout: Duration) -> Self
    where
        F: Future<Output = io::Result<S>> + Send + 'static,
        S: Stream + 'static,
    {
        Self {
            open: Arc::new(move || {
                let opening = open();
                Box::pin(async move { Ok(Box::new(opening.await?) as Box<dyn Stream>) })
            }),
            timeout,
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
        let exchange = async {
            let lost = |error: io::Error| RpcError::Link(error.to_string());
            let mut stream = BufReader::new((self.open)().await.map_err(lost)?);
            stream
                .get_mut()
                .write_all(encode_line(&request).as_bytes())
                .await
                .map_err(lost)?;
            let mut line = String::new();
            if stream.read_line(&mut line).await.map_err(lost)? == 0 {
                return Err(RpcError::Link(
                    "the server closed the stream unanswered".into(),
                ));
            }
            let response: Response =
                decode_line(&line).map_err(|error| RpcError::Link(error.to_string()))?;
            Ok(response?)
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| RpcError::Link(format!("no answer within {:?}", self.timeout)))?
    }
}

fn unexpected(reply: &Reply) -> RpcError {
    RpcError::Link(format!("an answer of the wrong kind: {reply:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::in_memory;
    use tokio::time::Instant;

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// An `Rpc` whose server answers every request with `answer`, after `delay` for a request about
    /// a target starting with `slow`.
    fn scripted(answer: Response, delay: Duration) -> Rpc {
        Rpc::new(
            move || {
                let answer = answer.clone();
                async move {
                    let (client, server) = tokio::io::duplex(4096);
                    tokio::spawn(async move {
                        let mut server = BufReader::new(server);
                        let mut line = String::new();
                        server.read_line(&mut line).await.unwrap();
                        if line.contains("\"slow") {
                            tokio::time::sleep(delay).await;
                        }
                        let _ = server
                            .get_mut()
                            .write_all(encode_line(&answer).as_bytes())
                            .await;
                    });
                    Ok(client)
                }
            },
            TIMEOUT,
        )
    }

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
        let rpc = in_memory();
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

    #[tokio::test(start_paused = true)]
    async fn a_slow_request_holds_up_no_other() {
        let rpc = scripted(Ok(Reply::Secret(b"t".to_vec())), Duration::from_secs(5));
        let slow = tokio::spawn({
            let rpc = rpc.clone();
            async move { rpc.read("slow:").await }
        });
        tokio::task::yield_now().await;
        let started = Instant::now();
        rpc.read("fast:").await.unwrap();
        assert_eq!(started.elapsed(), Duration::ZERO);
        slow.await.unwrap().unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn a_request_that_times_out_fails_alone() {
        let rpc = scripted(Ok(Reply::Secret(b"t".to_vec())), Duration::from_secs(60));
        let started = Instant::now();
        assert!(matches!(rpc.read("slow:").await, Err(RpcError::Link(_))));
        assert_eq!(started.elapsed(), TIMEOUT);
        assert_eq!(rpc.read("fast:").await.unwrap(), b"t");
    }

    #[tokio::test(start_paused = true)]
    async fn an_abandoned_request_leaves_the_next_one_its_own_answer() {
        let rpc = in_memory();
        rpc.write("gh:a:", "", b"a").await.unwrap();
        rpc.write("gh:b:", "", b"b").await.unwrap();
        let abandoned = tokio::time::timeout(Duration::ZERO, rpc.read("gh:a:")).await;
        assert!(abandoned.is_err());
        assert_eq!(rpc.read("gh:b:").await.unwrap(), b"b");
    }

    #[tokio::test]
    async fn a_stream_that_cant_open_is_a_link_error() {
        let rpc = Rpc::new(
            || async { Err::<tokio::io::DuplexStream, _>(io::Error::other("mux is gone")) },
            TIMEOUT,
        );
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
    }

    #[tokio::test]
    async fn a_stream_closed_without_an_answer_is_a_link_error() {
        let rpc = Rpc::new(
            || async {
                let (client, server) = tokio::io::duplex(1024);
                drop(server);
                Ok(client)
            },
            TIMEOUT,
        );
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
    }

    #[tokio::test]
    async fn an_answer_of_the_wrong_kind_is_a_link_error() {
        let rpc = scripted(Ok(Reply::Done), Duration::ZERO);
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
    }
}
