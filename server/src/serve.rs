//! One stream, one request: read the request line, answer it from the store, close.

use std::io;
use std::sync::Arc;

use credrelay_protocol::{CredentialStore, answer};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

/// Answers the one request on `stream`. The store is called on the blocking pool: the Credential
/// Manager's calls block, and the requests on other streams carry on meanwhile.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only Windows has a store to serve from")
)]
pub async fn serve_stream(
    store: Arc<impl CredentialStore + Send + Sync + 'static>,
    stream: impl AsyncRead + AsyncWrite + Unpin,
) -> io::Result<()> {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    stream.read_line(&mut line).await?;
    let answered = tokio::task::spawn_blocking(move || answer(&*store, &line))
        .await
        .map_err(io::Error::other)?;
    let answer = answered.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let stream = stream.get_mut();
    stream.write_all(answer.as_bytes()).await?;
    stream.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use credrelay_protocol::{MemoryStore, Reply, Request, Response, decode_line, encode_line};

    async fn exchange(store: &Arc<MemoryStore>, request: &str) -> (io::Result<()>, String) {
        let (mut client, server) = tokio::io::duplex(4096);
        let served = tokio::spawn(serve_stream(store.clone(), server));
        client.write_all(request.as_bytes()).await.unwrap();
        let mut answer = String::new();
        BufReader::new(&mut client)
            .read_line(&mut answer)
            .await
            .unwrap();
        (served.await.unwrap(), answer)
    }

    #[tokio::test]
    async fn each_stream_gets_the_answer_to_its_request() {
        let store = Arc::new(MemoryStore::default());
        let write = encode_line(&Request::Write {
            target: "gh:github.com:".into(),
            username: String::new(),
            secret: b"t".to_vec(),
        });
        let (result, answer) = exchange(&store, &write).await;
        result.unwrap();
        assert_eq!(decode_line::<Response>(&answer).unwrap(), Ok(Reply::Done));
        let (_, answer) =
            exchange(&store, "{\"op\":\"read\",\"target\":\"gh:github.com:\"}\n").await;
        assert_eq!(
            decode_line::<Response>(&answer).unwrap(),
            Ok(Reply::Secret(b"t".to_vec()))
        );
    }

    #[tokio::test]
    async fn a_stream_that_doesnt_carry_a_request_gets_no_answer() {
        let store = Arc::new(MemoryStore::default());
        let (result, answer) = exchange(&store, "not json\n").await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(answer.is_empty());
    }
}
