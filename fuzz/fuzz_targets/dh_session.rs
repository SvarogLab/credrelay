//! Any D-Bus client sends the public key a session is negotiated against, and the IV and
//! ciphertext of every secret it stores. None of them may panic the service, and a secret the
//! service encodes must decode back unchanged.

#![no_main]

use credrelay_client::fuzzing::{DH_AES, Encoding, EncodingError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)| {
    let (client_public, parameters, value, secret) = input;
    let encoding = match Encoding::negotiate(DH_AES, &client_public) {
        Ok((encoding, service_public)) => {
            assert!(!service_public.is_empty() && service_public.len() <= 128);
            encoding
        }
        Err(EncodingError::PublicKeyOutOfRange) => return,
        Err(other) => panic!("{other}"),
    };
    let (iv, sent) = encoding.encode(&secret).unwrap();
    assert_eq!(encoding.decode(&iv, &sent).unwrap(), secret);
    let _ = encoding.decode(&parameters, &value);
});
