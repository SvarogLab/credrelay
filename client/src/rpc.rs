use credrelay_protocol::{Credential, Failure, Reply, Request, Response, decode_line, encode_line};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use tokio::sync::{Mutex, watch};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error(transparent)]
    Failed(#[from] Failure),
    #[error("lost the link to credrelay-server: {0}")]
    Link(String),
}

/// The client's end of the server's stdio. Requests go one at a time: the protocol carries no
/// request ids, so an answer belongs to whichever request is in flight.
///
/// That makes the link fragile in one way: once an answer goes missing, arrives late or belongs to
/// another request, every later answer would be read as the wrong one. So any of those breaks the
/// link for good, every later call fails at once, and [`Rpc::broken`] tells the owner to start over.
#[derive(Clone)]
pub struct Rpc {
    shared: Arc<Shared>,
}

struct Shared {
    link: Mutex<Link>,
    timeout: Duration,
    broken: watch::Sender<bool>,
}

struct Link {
    reader: BufReader<Box<dyn AsyncRead + Send + Unpin>>,
    writer: Box<dyn AsyncWrite + Send + Unpin>,
}

/// Breaks the link when dropped before [`BreakUnlessFinished::finish`]: an exchange that didn't
/// finish, whether it failed, timed out, or its caller stopped waiting, left the link out of step.
struct BreakUnlessFinished<'a> {
    broken: Option<&'a watch::Sender<bool>>,
}

impl BreakUnlessFinished<'_> {
    fn finish(mut self) {
        self.broken = None;
    }
}

impl Drop for BreakUnlessFinished<'_> {
    fn drop(&mut self) {
        if let Some(broken) = self.broken {
            broken.send_replace(true);
        }
    }
}

impl Rpc {
    /// Speaks to the server over `reader` and `writer`, giving it `timeout` to answer each
    /// request.
    pub fn new(
        reader: impl AsyncRead + Send + Unpin + 'static,
        writer: impl AsyncWrite + Send + Unpin + 'static,
        timeout: Duration,
    ) -> Self {
        Self {
            shared: Arc::new(Shared {
                link: Mutex::new(Link {
                    reader: BufReader::new(Box::new(reader)),
                    writer: Box::new(writer),
                }),
                timeout,
                broken: watch::Sender::new(false),
            }),
        }
    }

    /// Resolves once the link is broken.
    pub async fn broken(&self) {
        let mut broken = self.shared.broken.subscribe();
        let _ = broken.wait_for(|broken| *broken).await;
    }

    pub async fn read(&self, target: &str) -> Result<Vec<u8>, RpcError> {
        let target = target.to_owned();
        match self.call(Request::Read { target }).await? {
            Reply::Secret(secret) => Ok(secret),
            other => Err(self.out_of_step(&other)),
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
            other => Err(self.out_of_step(&other)),
        }
    }

    pub async fn delete(&self, target: &str) -> Result<(), RpcError> {
        let target = target.to_owned();
        match self.call(Request::Delete { target }).await? {
            Reply::Done => Ok(()),
            other => Err(self.out_of_step(&other)),
        }
    }

    pub async fn list(&self, prefix: &str) -> Result<Vec<Credential>, RpcError> {
        let prefix = prefix.to_owned();
        match self.call(Request::List { prefix }).await? {
            Reply::Credentials(credentials) => Ok(credentials),
            other => Err(self.out_of_step(&other)),
        }
    }

    async fn call(&self, request: Request) -> Result<Reply, RpcError> {
        let mut link = self.shared.link.lock().await;
        if *self.shared.broken.borrow() {
            return Err(RpcError::Link("the link is broken".into()));
        }
        let unfinished = BreakUnlessFinished {
            broken: Some(&self.shared.broken),
        };
        let line = tokio::time::timeout(self.shared.timeout, exchange(&mut link, &request))
            .await
            .map_err(|_| RpcError::Link(format!("no answer within {:?}", self.shared.timeout)))??;
        let response: Response =
            decode_line(&line).map_err(|error| RpcError::Link(error.to_string()))?;
        unfinished.finish();
        Ok(response?)
    }

    fn out_of_step(&self, reply: &Reply) -> RpcError {
        self.shared.broken.send_replace(true);
        RpcError::Link(format!("answer out of step with the request: {reply:?}"))
    }
}

/// Sends `request` and reads one line of answer.
async fn exchange(link: &mut Link, request: &Request) -> Result<String, RpcError> {
    let lost = |error: std::io::Error| RpcError::Link(error.to_string());
    link.writer
        .write_all(encode_line(request).as_bytes())
        .await
        .map_err(lost)?;
    link.writer.flush().await.map_err(lost)?;
    let mut line = String::new();
    if link.reader.read_line(&mut line).await.map_err(lost)? == 0 {
        return Err(RpcError::Link("the server closed its output".into()));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::in_memory;

    use std::time::Duration;
    use tokio::time::Instant;

    const TIMEOUT: Duration = Duration::from_secs(10);

    /// An `Rpc` whose server reads requests and never answers, kept alive by the returned handle.
    fn silent() -> (Rpc, tokio::io::DuplexStream) {
        let (client, server) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client);
        (Rpc::new(reader, writer, TIMEOUT), server)
    }

    #[tokio::test(start_paused = true)]
    async fn a_server_that_never_answers_fails_the_call_in_time_and_breaks_the_link() {
        let (rpc, _server) = silent();
        let started = Instant::now();
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
        assert_eq!(started.elapsed(), TIMEOUT);
        tokio::time::timeout(Duration::from_secs(1), rpc.broken())
            .await
            .expect("a timed-out link is broken");

        let started = Instant::now();
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
        assert_eq!(started.elapsed(), Duration::ZERO);
    }

    /// The answer to an abandoned request would arrive as the answer to the next one.
    #[tokio::test(start_paused = true)]
    async fn a_call_abandoned_halfway_breaks_the_link() {
        let (rpc, _server) = silent();
        let abandoned =
            tokio::time::timeout(Duration::from_secs(1), rpc.read("gh:github.com:")).await;
        assert!(abandoned.is_err());
        tokio::time::timeout(Duration::from_secs(1), rpc.broken())
            .await
            .expect("an abandoned call breaks the link");
    }

    #[tokio::test(start_paused = true)]
    async fn a_link_that_answers_stays_whole() {
        let rpc = in_memory();
        rpc.write("gh:github.com:", "", b"t").await.unwrap();
        rpc.read("gh:github.com:").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(60), rpc.broken())
                .await
                .is_err()
        );
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
        let rpc = Rpc::new(reader, writer, TIMEOUT);
        assert!(matches!(
            rpc.read("gh:github.com:").await,
            Err(RpcError::Link(_))
        ));
        rpc.broken().await;
    }

    #[tokio::test]
    async fn an_answer_of_the_wrong_kind_is_a_link_error() {
        let (client, server) = tokio::io::duplex(1024);
        let (reader, writer) = tokio::io::split(client);
        let rpc = Rpc::new(reader, writer, TIMEOUT);
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
