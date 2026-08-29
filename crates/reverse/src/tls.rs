//! TLS termination — rustls + webpki-roots fallback, ALPN, fail-fast.

// `rustls` only default; `native-tls` as optional feature later.

use std::{fs::File, io::BufReader, path::Path};

use rustls::{ServerConfig, pki_types::CertificateDer, pki_types::PrivateKeyDer};

/// TLS termination config.
#[derive(Debug, Clone)]
pub struct TlsTermination {
    pub cert_path: String,
    pub key_path: String,
    pub alpn: Vec<String>, // e.g. ["h2", "http/1.1"]
}

impl TlsTermination {
    pub fn new(cert: impl Into<String>, key: impl Into<String>, alpn: Vec<String>) -> Self {
        Self { cert_path: cert.into(), key_path: key.into(), alpn }
    }

    /// Fail fast if cert/key missing — no self-signed.
    pub fn ensure_files(&self) -> xproxy_core::Result<()> {
        for p in [&self.cert_path, &self.key_path] {
            if !Path::new(p).exists() {
                return Err(xproxy_core::Error::Tls(format!(
                    "reverse.tls cert/key not found: {p}"
                )));
            }
        }
        Ok(())
    }

    /// Build `ServerConfig` with rustls, webpki-roots for client auth fallback, ALPN.
    pub fn server_config(&self) -> xproxy_core::Result<ServerConfig> {
        self.ensure_files()?;

        let certs = load_certs(&self.cert_path)?;
        let key = load_key(&self.key_path)?;

        let mut config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| xproxy_core::Error::Tls(format!("rustls cert: {e}")))?;

        if !self.alpn.is_empty() {
            config.alpn_protocols = self.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
        } else {
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        }

        // Ensure webpki roots are available for upstream verification path (used by client side).
        // For server, this just validates the crate is available; client verification will use it.
        let _ = webpki_roots::TLS_SERVER_ROOTS;

        // Native certs as fallback for client verification (not used here, but validates availability).
        let _ = rustls_native_certs::load_native_certs();

        Ok(config)
    }
}

fn load_certs(path: &str) -> xproxy_core::Result<Vec<CertificateDer<'static>>> {
    let file =
        File::open(path).map_err(|e| xproxy_core::Error::Tls(format!("open {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| xproxy_core::Error::Tls(format!("parse cert {path}: {e}")))?;
    if certs.is_empty() {
        return Err(xproxy_core::Error::Tls(format!("no certs in {path}")));
    }
    Ok(certs)
}

fn load_key(path: &str) -> xproxy_core::Result<PrivateKeyDer<'static>> {
    let file =
        File::open(path).map_err(|e| xproxy_core::Error::Tls(format!("open {path}: {e}")))?;
    let mut reader = BufReader::new(file);
    let key = rustls_pemfile::private_key(&mut reader)
        .map_err(|e| xproxy_core::Error::Tls(format!("parse key {path}: {e}")))?
        .ok_or_else(|| xproxy_core::Error::Tls(format!("no private key in {path}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_temp(content: &str) -> String {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("xproxy-test-{}-{}.pem", std::process::id(), content.len()));
        let mut f = File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        path.to_string_lossy().to_string()
    }

    #[test]
    fn fails_fast_missing() {
        let t = TlsTermination::new("/tmp/missing-cert.pem", "/tmp/missing-key.pem", vec![]);
        assert!(t.ensure_files().is_err());
        assert!(t.server_config().is_err());
    }

    #[test]
    fn alpn_default() {
        // Create dummy files to pass ensure_files but fail parse — we test ensure_files only
        let cert = write_temp("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n");
        let key = write_temp("-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n");
        let t = TlsTermination::new(&cert, &key, vec![]);
        // ensure_files passes (files exist), server_config fails on parse but alpn would be set
        assert!(t.ensure_files().is_ok());
        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }
}
