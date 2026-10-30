//! The server's diagnostics, passed on line by line and marked as the server's.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tracing_subscriber::EnvFilter;

pub const PREFIX: &str = "server: ";

/// Copies each line from `server_stderr` to `out` behind [`PREFIX`], as it is otherwise: the level
/// and fields the server wrote stay as they were. Ends when the server's stderr does.
pub async fn forward(server_stderr: impl AsyncRead + Unpin, mut out: impl AsyncWrite + Unpin) {
    let mut lines = BufReader::new(server_stderr);
    let mut line = Vec::new();
    loop {
        line.clear();
        match lines.read_until(b'\n', &mut line).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
        // A Windows process may end its lines with \r\n.
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches(['\n', '\r']);
        let marked = format!("{PREFIX}{text}\n");
        if out.write_all(marked.as_bytes()).await.is_err() || out.flush().await.is_err() {
            return;
        }
    }
}

/// The filter both processes run: `RUST_LOG`, or `info` when it is unset or empty. A value that
/// doesn't parse is an error here rather than ignored, since the server would refuse it and exit.
pub fn filter(rust_log: Option<String>) -> Result<(String, EnvFilter), String> {
    let filter = rust_log
        .filter(|filter| !filter.is_empty())
        .unwrap_or_else(|| "info".to_owned());
    let parsed =
        EnvFilter::try_new(&filter).map_err(|error| format!("invalid RUST_LOG: {error}"))?;
    Ok((filter, parsed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn every_line_is_marked_including_a_last_one_without_a_newline() {
        let input: &[u8] = b"INFO started\r\nWARN slow\n\xffbyte\nlast";
        let mut out = Vec::new();
        forward(input, &mut out).await;
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "server: INFO started\nserver: WARN slow\nserver: \u{fffd}byte\nserver: last\n"
        );
    }

    #[test]
    fn the_server_gets_the_clients_filter_or_info() {
        assert_eq!(
            filter(Some("debug,zbus=warn".into())).unwrap().0,
            "debug,zbus=warn"
        );
        assert_eq!(filter(Some(String::new())).unwrap().0, "info");
        assert_eq!(filter(None).unwrap().0, "info");
    }

    #[test]
    fn a_filter_that_doesnt_parse_is_an_error_naming_rust_log() {
        let error = filter(Some("x=loud".into())).unwrap_err();
        assert!(error.starts_with("invalid RUST_LOG: "), "{error}");
    }
}
