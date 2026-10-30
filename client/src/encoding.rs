//! The transfer encodings a Secret Service session negotiates, as `OpenSession` names them.
//!
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7` is the one encrypted algorithm the specification defines:
//! a Diffie-Hellman exchange in the RFC 2409 second Oakley group, HKDF-SHA256 with no salt and no
//! info over the shared secret padded to the group size, and AES-128-CBC with PKCS#7 padding under
//! a fresh IV per secret, sent as the secret's parameters.

use aes::Aes128;
use cbc::cipher::block_padding::Pkcs7;
use cbc::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hkdf::Hkdf;
use num_bigint::BigUint;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const PLAIN: &str = "plain";
pub const DH_AES: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

const OAKLEY_GROUP_2_PRIME: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74",
    "020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437",
    "4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
);
const GROUP_BYTES: usize = 128;
const IV_BYTES: usize = 16;

type AesKey = Zeroizing<[u8; 16]>;
#[derive(Debug, thiserror::Error)]
pub enum EncodingError {
    #[error("unsupported algorithm {0:?}")]
    Unsupported(String),
    #[error("malformed session parameters: {0}")]
    Malformed(String),
    #[error("no randomness for a key or IV: {0}")]
    Random(String),
}

/// How secrets cross the bus in one session.
pub enum Encoding {
    Plain,
    Aes(AesKey),
}

impl Encoding {
    /// Negotiates `algorithm` against the client's `input`, returning the encoding and the
    /// output `OpenSession` hands back: nothing for plain, the service's public key for DH.
    pub fn negotiate(algorithm: &str, input: &[u8]) -> Result<(Self, Vec<u8>), EncodingError> {
        match algorithm {
            PLAIN => Ok((Self::Plain, Vec::new())),
            DH_AES => {
                let prime = BigUint::parse_bytes(OAKLEY_GROUP_2_PRIME.as_bytes(), 16)
                    .expect("the group prime is valid hex");
                let client_public = BigUint::from_bytes_be(input);
                if client_public <= BigUint::from(1u8) || client_public >= &prime - 1u8 {
                    return Err(EncodingError::Malformed(
                        "client public key out of range".into(),
                    ));
                }
                let mut private_bytes = Zeroizing::new([0u8; GROUP_BYTES]);
                getrandom::fill(private_bytes.as_mut_slice())
                    .map_err(|error| EncodingError::Random(error.to_string()))?;
                let private = BigUint::from_bytes_be(private_bytes.as_slice());
                let public = BigUint::from(2u8).modpow(&private, &prime);
                let shared = Zeroizing::new(client_public.modpow(&private, &prime).to_bytes_be());

                let mut padded = Zeroizing::new([0u8; GROUP_BYTES]);
                padded[GROUP_BYTES - shared.len()..].copy_from_slice(&shared);
                let mut key = Zeroizing::new([0u8; 16]);
                Hkdf::<Sha256>::new(None, padded.as_slice())
                    .expand(&[], key.as_mut_slice())
                    .expect("16 bytes is a valid HKDF-SHA256 output length");
                Ok((Self::Aes(key), public.to_bytes_be()))
            }
            other => Err(EncodingError::Unsupported(other.to_owned())),
        }
    }

    /// Returns `(parameters, value)` as a `Secret` struct carries them.
    pub fn encode(&self, secret: &[u8]) -> Result<(Vec<u8>, Vec<u8>), EncodingError> {
        match self {
            Self::Plain => Ok((Vec::new(), secret.to_vec())),
            Self::Aes(key) => {
                let mut iv = [0u8; IV_BYTES];
                getrandom::fill(&mut iv)
                    .map_err(|error| EncodingError::Random(error.to_string()))?;
                let value = cbc::Encryptor::<Aes128>::new_from_slices(key.as_slice(), &iv)
                    .expect("AES-128-CBC takes a 16-byte key and IV")
                    .encrypt_padded_vec::<Pkcs7>(secret);
                Ok((iv.to_vec(), value))
            }
        }
    }

    pub fn decode(&self, parameters: &[u8], value: &[u8]) -> Result<Vec<u8>, EncodingError> {
        match self {
            Self::Plain => Ok(value.to_vec()),
            Self::Aes(key) => {
                let iv: [u8; IV_BYTES] = parameters
                    .try_into()
                    .map_err(|_| EncodingError::Malformed("the IV is not 16 bytes".into()))?;
                cbc::Decryptor::<Aes128>::new_from_slices(key.as_slice(), &iv)
                    .expect("AES-128-CBC takes a 16-byte key and IV")
                    .decrypt_padded_vec::<Pkcs7>(value)
                    .map_err(|error| EncodingError::Malformed(error.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oo7::Key;
    use oo7::crypto;

    #[test]
    fn plain_passes_secrets_through_with_no_parameters() {
        let (encoding, output) = Encoding::negotiate(PLAIN, &[]).unwrap();
        assert!(output.is_empty());
        let (parameters, value) = encoding.encode(b"t0ken").unwrap();
        assert!(parameters.is_empty());
        assert_eq!(value, b"t0ken");
        assert_eq!(encoding.decode(&[], b"t0ken").unwrap(), b"t0ken");
    }

    /// The client half is what libsecret and the Rust `keyring` stores do: derive the same AES key
    /// from the service's public key, and encrypt or decrypt with a fresh IV per secret.
    #[test]
    fn dh_agrees_on_a_key_with_the_client_in_both_directions() {
        let client_private = Key::generate_private_key().unwrap();
        let client_public = Key::generate_public_key(&client_private).unwrap();
        let (encoding, service_public) =
            Encoding::negotiate(DH_AES, client_public.as_ref()).unwrap();
        let client_key = Key::generate_aes_key(&client_private, &Key::new(service_public)).unwrap();

        let (iv, value) = encoding.encode(b"t0ken").unwrap();
        assert_ne!(value, b"t0ken");
        assert_eq!(
            &*crypto::decrypt(&value, &client_key, &iv).unwrap(),
            b"t0ken"
        );

        let iv = crypto::generate_iv().unwrap();
        let sent = crypto::encrypt(b"other", &client_key, &iv).unwrap();
        assert_eq!(encoding.decode(&iv, &sent).unwrap(), b"other");
    }

    #[test]
    fn an_unknown_algorithm_is_unsupported() {
        assert!(matches!(
            Encoding::negotiate("dh-ietf2048-sha512", &[]),
            Err(EncodingError::Unsupported(_))
        ));
    }

    /// Only a secret that can't be AES-CBC at all is rejected every time: the algorithm carries no
    /// MAC, so a whole block of garbage decrypts to valid padding about once in 256 tries.
    #[test]
    fn a_dh_secret_that_isnt_whole_blocks_or_has_a_short_iv_is_malformed() {
        let client_private = Key::generate_private_key().unwrap();
        let client_public = Key::generate_public_key(&client_private).unwrap();
        let (encoding, _) = Encoding::negotiate(DH_AES, client_public.as_ref()).unwrap();
        assert!(matches!(
            encoding.decode(&[0; 16], &[1; 15]),
            Err(EncodingError::Malformed(_))
        ));
        assert!(matches!(
            encoding.decode(&[0; 15], &[1; 16]),
            Err(EncodingError::Malformed(_))
        ));
    }
}
