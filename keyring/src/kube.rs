//! A kubectl exec credential plugin.
//!
//! The secret is the kubeconfig `user` entry it replaces, as JSON:
//! `{"token": …}`, or `{"client-certificate-data": …, "client-key-data": …}` with base64 PEM as
//! kubeconfig holds it, so `kubectl config view --raw -o jsonpath='{.users[?(@.name=="…")].user}'`
//! prints exactly what to store.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum KubeError {
    #[error("the stored credential isn't a kubeconfig user entry: {0}")]
    NotUserEntry(#[from] serde_json::Error),
    #[error("the stored user entry holds neither a token nor a client certificate and key")]
    NoCredential,
    #[error("a certificate or key in the stored user entry isn't base64: {0}")]
    NotBase64(#[from] base64::DecodeError),
    #[error("a certificate or key in the stored user entry isn't PEM text: {0}")]
    NotText(#[from] std::string::FromUtf8Error),
}

/// The `ExecCredential` kubectl reads from the plugin's stdout, for the stored `user` entry.
pub fn exec_credential(stored: &[u8]) -> Result<String, KubeError> {
    let user: User = serde_json::from_slice(stored)?;
    let status = match user {
        User {
            token: Some(token), ..
        } => Status::Token { token },
        User {
            client_certificate_data: Some(certificate),
            client_key_data: Some(key),
            ..
        } => Status::ClientCertificate {
            client_certificate_data: pem(&certificate)?,
            client_key_data: pem(&key)?,
        },
        _ => return Err(KubeError::NoCredential),
    };
    let credential = ExecCredential {
        api_version: "client.authentication.k8s.io/v1",
        kind: "ExecCredential",
        status,
    };
    Ok(serde_json::to_string(&credential).expect("an ExecCredential always serializes"))
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct User {
    token: Option<String>,
    client_certificate_data: Option<String>,
    client_key_data: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExecCredential {
    api_version: &'static str,
    kind: &'static str,
    status: Status,
}

#[derive(Serialize)]
#[serde(untagged, rename_all_fields = "camelCase")]
enum Status {
    Token {
        token: String,
    },
    ClientCertificate {
        client_certificate_data: String,
        client_key_data: String,
    },
}

/// kubeconfig holds certificates and keys base64-encoded; an `ExecCredential` carries them as PEM.
fn pem(data: &str) -> Result<String, KubeError> {
    Ok(String::from_utf8(STANDARD.decode(data)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn parsed(output: &str) -> Value {
        serde_json::from_str(output).unwrap()
    }

    #[test]
    fn a_client_certificate_is_handed_over_as_pem() {
        let stored = json!({
            "client-certificate-data": STANDARD.encode("certificate PEM\n"),
            "client-key-data": STANDARD.encode("key PEM\n"),
        });
        let output = exec_credential(stored.to_string().as_bytes()).unwrap();
        assert_eq!(
            parsed(&output),
            json!({
                "apiVersion": "client.authentication.k8s.io/v1",
                "kind": "ExecCredential",
                "status": {
                    "clientCertificateData": "certificate PEM\n",
                    "clientKeyData": "key PEM\n",
                },
            })
        );
    }

    #[test]
    fn a_token_is_handed_over_as_it_is() {
        let output = exec_credential(br#"{"token":"t0ken"}"#).unwrap();
        assert_eq!(parsed(&output)["status"], json!({"token": "t0ken"}));
    }

    #[test]
    fn anything_else_is_refused_with_what_is_wrong_with_it() {
        assert!(matches!(
            exec_credential(b"not json"),
            Err(KubeError::NotUserEntry(_))
        ));
        for stored in [
            &br#"{"username":"admin"}"#[..],
            br#"{"client-certificate-data":"AAAA"}"#,
        ] {
            assert!(
                matches!(exec_credential(stored), Err(KubeError::NoCredential)),
                "{}",
                String::from_utf8_lossy(stored)
            );
        }
        assert!(matches!(
            exec_credential(
                br#"{"client-certificate-data":"not base64!","client-key-data":"AAAA"}"#
            ),
            Err(KubeError::NotBase64(_))
        ));
        assert!(matches!(
            exec_credential(br#"{"client-certificate-data":"/w==","client-key-data":"/w=="}"#),
            Err(KubeError::NotText(_))
        ));
    }
}
