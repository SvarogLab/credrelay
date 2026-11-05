//! Any D-Bus client sends the public key a session is negotiated against, and the IV and
//! ciphertext of every secret it stores. None of them may panic the service, and a secret the
//! service encodes must decode back unchanged.

#![no_main]

use std::sync::LazyLock;

use credrelay_client::fuzzing::{DH_AES, Encoding, EncodingError};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;

/// The exchange is fuzzed apart from the negotiation, whose modular exponentiation would otherwise
/// leave time for a few dozen inputs a second.
#[derive(Arbitrary, Debug)]
enum Input {
    Negotiate(Vec<u8>),
    Exchange {
        parameters: Vec<u8>,
        value: Vec<u8>,
        secret: Vec<u8>,
    },
}

static SESSION: LazyLock<Encoding> =
    LazyLock::new(|| Encoding::negotiate(DH_AES, &[2]).expect("2 is a valid public key").0);

fuzz_target!(|input: Input| match input {
    Input::Negotiate(client_public) => match Encoding::negotiate(DH_AES, &client_public) {
        Ok((_, service_public)) => {
            assert!(!service_public.is_empty() && service_public.len() <= 128);
        }
        Err(EncodingError::PublicKeyOutOfRange) => {}
        Err(other) => panic!("{other}"),
    },
    Input::Exchange {
        parameters,
        value,
        secret,
    } => {
        let (iv, sent) = SESSION.encode(&secret).unwrap();
        assert_eq!(SESSION.decode(&iv, &sent).unwrap(), secret);
        let _ = SESSION.decode(&parameters, &value);
    }
});
