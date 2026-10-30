//! The server's diagnostics, passed on line by line and marked as the server's.

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

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

/// The filter the server is started with: the client's own `RUST_LOG`, or `info` without one.
pub fn filter(rust_log: Option<String>) -> String {
    rust_log
        .filter(|filter| !filter.is_empty())
        .unwrap_or_else(|| "info".to_owned())
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
        assert_eq!(filter(Some("debug,zbus=warn".into())), "debug,zbus=warn");
        assert_eq!(filter(Some(String::new())), "info");
        assert_eq!(filter(None), "info");
    }
}
