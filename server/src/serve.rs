use std::io::{self, BufRead, Write};

use credrelay_protocol::{Allowlist, CredentialStore, Request, decode_line, encode_line, handle};

/// Answers requests from `input` on `output`, one line each, until `input` ends.
///
/// A line that isn't a request ends the loop with an error: the client never sends one, so the
/// stream is out of step and every later answer would land on the wrong question.
#[cfg_attr(
    not(windows),
    allow(dead_code, reason = "only Windows has a store to serve from")
)]
pub fn serve(
    store: &impl CredentialStore,
    allowlist: &Allowlist,
    input: impl BufRead,
    mut output: impl Write,
) -> io::Result<()> {
    for line in input.lines() {
        let request: Request = decode_line(&line?)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let response = handle(store, allowlist, request);
        output.write_all(encode_line(&response).as_bytes())?;
        output.flush()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use credrelay_protocol::{MemoryStore, Reply, Response};

    fn run(input: &str) -> (io::Result<()>, Vec<Response>) {
        let store = MemoryStore::default();
        let allowlist = Allowlist::new(vec!["gh:".into()]).unwrap();
        let mut output = Vec::new();
        let result = serve(&store, &allowlist, input.as_bytes(), &mut output);
        let responses = String::from_utf8(output)
            .unwrap()
            .lines()
            .map(|line| decode_line(line).unwrap())
            .collect();
        (result, responses)
    }

    #[test]
    fn answers_each_line_in_order_and_stops_cleanly_at_the_end() {
        let (result, responses) = run(concat!(
            r#"{"op":"write","target":"gh:github.com:","username":"","secret":[116]}"#,
            "\n",
            r#"{"op":"read","target":"gh:github.com:"}"#,
            "\n",
        ));
        result.unwrap();
        assert_eq!(
            responses,
            vec![Ok(Reply::Done), Ok(Reply::Secret(b"t".to_vec()))]
        );
    }

    #[test]
    fn a_malformed_line_stops_the_loop_with_an_error() {
        let (result, responses) = run(concat!(
            "not json\n",
            r#"{"op":"read","target":"gh:github.com:"}"#,
            "\n",
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
        assert!(responses.is_empty());
    }
}
