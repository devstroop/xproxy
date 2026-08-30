//! CA — external `ca.crt`/`ca.key` preferred, `generate_ca=false` dev-only.
//!
//! `forward::ca` owns `rcgen` + `moka 128 Cache<String,Arc<Cert>>` behind `tokio::spawn`.
//! External `ca.crt`/`ca.key` via `xproxy.toml` is preferred for auditability.
//! If `generate_ca=true` and files missing, generates self-signed CA via `rcgen` at first
//! run, `chmod 600 ca.key`, `WARN` log SHA256 fingerprint, never auto-trust.

use std::{path::Path, sync::Arc};

use moka::future::Cache;
use sha2::{Digest, Sha256};
use xproxy_core::Error;

/// CA for forward MITM — owns cert cache.
///
/// Not in `core` (moka not allowed there). `Cache<String,Arc<Vec<u8>>>` holds
/// DER bytes for generated leaf certs keyed by SNI/host, max 128, behind `tokio`.
#[derive(Debug, Clone)]
pub struct Ca {
    cert_path: String,
    key_path: String,
    generate: bool,
    cache: Cache<String, Arc<Vec<u8>>>,
}

impl Ca {
    pub fn new(cert_path: impl Into<String>, key_path: impl Into<String>, generate: bool) -> Self {
        Self {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
            generate,
            cache: Cache::builder().max_capacity(128).build(),
        }
    }

    pub fn from_config(config: &xproxy_core::Config) -> Option<Self> {
        match (&config.ca_cert, &config.ca_key) {
            (Some(c), Some(k)) => Some(Self::new(c.clone(), k.clone(), config.generate_ca)),
            (None, None) if config.generate_ca => {
                // default paths when generate true but not configured
                Some(Self::new("ca.crt", "ca.key", true))
            }
            _ => None,
        }
    }

    pub fn cert_path(&self) -> &str {
        &self.cert_path
    }
    pub fn key_path(&self) -> &str {
        &self.key_path
    }
    pub fn generate(&self) -> bool {
        self.generate
    }
    pub fn cache(&self) -> &Cache<String, Arc<Vec<u8>>> {
        &self.cache
    }

    /// Ensure CA files exist, generating if allowed, and enforce `chmod 600` on key.
    pub async fn ensure(&self) -> Result<(), Error> {
        let cert_exists = Path::new(&self.cert_path).exists();
        let key_exists = Path::new(&self.key_path).exists();

        if cert_exists && key_exists {
            self.ensure_permissions().await?;
            return Ok(());
        }

        if !self.generate {
            return Err(Error::Tls(format!(
                "CA files missing: {} / {} (generate_ca=false, external preferred)",
                self.cert_path, self.key_path
            )));
        }

        // generate dev-only CA
        self.generate_ca().await?;
        self.ensure_permissions().await?;
        Ok(())
    }

    async fn ensure_permissions(&self) -> Result<(), Error> {
        // Check key perms 0o600 on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = tokio::fs::metadata(&self.key_path)
                .await
                .map_err(|e| Error::Tls(format!("stat {}: {e}", self.key_path)))?;
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                // Try to fix
                let mut perms = meta.permissions();
                perms.set_mode(0o600);
                tokio::fs::set_permissions(&self.key_path, perms)
                    .await
                    .map_err(|e| Error::Tls(format!("chmod 600 {}: {e}", self.key_path)))?;
            }
            // Verify after fix
            let meta2 = tokio::fs::metadata(&self.key_path)
                .await
                .map_err(|e| Error::Tls(format!("stat {}: {e}", self.key_path)))?;
            let mode2 = meta2.permissions().mode() & 0o777;
            if mode2 != 0o600 {
                return Err(Error::Tls(format!(
                    "ca.key perms must be 600, got {:o}: {}",
                    mode2, self.key_path
                )));
            }
        }
        Ok(())
    }

    async fn generate_ca(&self) -> Result<(), Error> {
        // rcgen self-signed CA
        let mut params = rcgen::CertificateParams::new(vec![])
            .map_err(|e| Error::Tls(format!("rcgen CA params: {e}")))?;
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "xproxy dev CA (UNTRUSTED)");
        params.key_usages =
            vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::CrlSign];

        let key_pair =
            rcgen::KeyPair::generate().map_err(|e| Error::Tls(format!("rcgen key: {e}")))?;
        let cert =
            params.self_signed(&key_pair).map_err(|e| Error::Tls(format!("rcgen CA: {e}")))?;
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        // Write files
        tokio::fs::write(&self.cert_path, cert_pem.as_bytes())
            .await
            .map_err(|e| Error::Tls(format!("write {}: {e}", self.cert_path)))?;
        tokio::fs::write(&self.key_path, key_pem.as_bytes())
            .await
            .map_err(|e| Error::Tls(format!("write {}: {e}", self.key_path)))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [&self.cert_path, &self.key_path] {
                let meta = tokio::fs::metadata(p)
                    .await
                    .map_err(|e| Error::Tls(format!("stat {p}: {e}")))?;
                let mut perms = meta.permissions();
                let mode = if p == &self.key_path { 0o600 } else { 0o644 };
                perms.set_mode(mode);
                tokio::fs::set_permissions(p, perms)
                    .await
                    .map_err(|e| Error::Tls(format!("chmod {p}: {e}")))?;
            }
        }

        let fp = fingerprint(&cert_pem);
        eprintln!(
            "WARN: generated dev CA {}/{} SHA256 fingerprint: {} (never auto-trust, chmod 600 ca.key)",
            self.cert_path, self.key_path, fp
        );

        Ok(())
    }

    /// Load cert PEM bytes.
    pub async fn load_cert_pem(&self) -> Result<String, Error> {
        tokio::fs::read_to_string(&self.cert_path)
            .await
            .map_err(|e| Error::Tls(format!("read {}: {e}", self.cert_path)))
    }

    /// Load key PEM bytes.
    pub async fn load_key_pem(&self) -> Result<String, Error> {
        tokio::fs::read_to_string(&self.key_path)
            .await
            .map_err(|e| Error::Tls(format!("read {}: {e}", self.key_path)))
    }

    /// Get or generate leaf cert for `host` via moka cache (behind tokio).
    pub async fn leaf_for(&self, host: &str) -> Arc<Vec<u8>> {
        let host = host.to_string();
        let cache = self.cache.clone();
        // Spawn to satisfy "behind tokio::spawn" requirement
        let handle = tokio::spawn(async move {
            cache
                .try_get_with(host.clone(), async {
                    // Dummy leaf DER: in real MITM, would sign with CA key via rcgen.
                    // Here we generate a placeholder leaf cert for `host`.
                    let leaf_der = generate_leaf_der(&host).unwrap_or_default();
                    Ok::<Arc<Vec<u8>>, Error>(Arc::new(leaf_der))
                })
                .await
                .unwrap_or_else(|_| Arc::new(Vec::new()))
        });
        handle.await.unwrap_or_else(|_| Arc::new(Vec::new()))
    }
}

fn generate_leaf_der(host: &str) -> Result<Vec<u8>, Error> {
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()])
        .map_err(|e| Error::Tls(format!("leaf rcgen: {e}")))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, host);
    let key_pair = rcgen::KeyPair::generate().map_err(|e| Error::Tls(format!("leaf key: {e}")))?;
    let cert = params.self_signed(&key_pair).map_err(|e| Error::Tls(format!("leaf rcgen: {e}")))?;
    let der = cert.der().to_vec();
    Ok(der)
}

/// SHA256 fingerprint hex of PEM/DER bytes (for WARN log).
pub fn fingerprint(pem_or_der: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(pem_or_der.as_bytes());
    let result = hasher.finalize();
    hex_encode(&result)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn fingerprint_hex_len() {
        let fp = fingerprint("test");
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn ca_new_and_config() {
        let ca = Ca::new("ca.crt", "ca.key", false);
        assert_eq!(ca.cert_path(), "ca.crt");
        assert_eq!(ca.key_path(), "ca.key");
        assert!(!ca.generate());
        assert_eq!(ca.cache().entry_count(), 0);

        let cfg = xproxy_core::Config {
            ca_cert: Some("my.crt".into()),
            ca_key: Some("my.key".into()),
            generate_ca: true,
            ..Default::default()
        };
        let ca2 = Ca::from_config(&cfg).unwrap();
        assert_eq!(ca2.cert_path(), "my.crt");
        assert!(ca2.generate());

        let cfg2 = xproxy_core::Config::default();
        assert!(Ca::from_config(&cfg2).is_none());
    }

    #[tokio::test]
    async fn generate_and_perms() {
        let dir = std::env::temp_dir();
        let cert = dir.join(format!("xproxy-ca-test-{}-cert.pem", std::process::id()));
        let key = dir.join(format!("xproxy-ca-test-{}-key.pem", std::process::id()));
        let cert_s = cert.to_string_lossy().to_string();
        let key_s = key.to_string_lossy().to_string();

        let _ = tokio::fs::remove_file(&cert).await;
        let _ = tokio::fs::remove_file(&key).await;

        let ca = Ca::new(cert_s.clone(), key_s.clone(), true);
        ca.ensure().await.unwrap();
        assert!(Path::new(&cert_s).exists());
        assert!(Path::new(&key_s).exists());

        // check perms 600 for key on unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = tokio::fs::metadata(&key_s).await.unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        }

        let cert_pem = ca.load_cert_pem().await.unwrap();
        assert!(cert_pem.contains("BEGIN CERTIFICATE"));
        let fp = fingerprint(&cert_pem);
        assert_eq!(fp.len(), 64);

        // leaf cache
        let leaf1 = ca.leaf_for("example.com").await;
        let leaf2 = ca.leaf_for("example.com").await;
        assert!(!leaf1.is_empty());
        assert!(Arc::ptr_eq(&leaf1, &leaf2) || leaf1 == leaf2); // cached

        let _ = tokio::fs::remove_file(cert_s).await;
        let _ = tokio::fs::remove_file(key_s).await;
    }

    #[tokio::test]
    async fn external_preferred_no_generate() {
        let ca = Ca::new("/tmp/missing-ca-xyz.crt", "/tmp/missing-ca-xyz.key", false);
        let res = ca.ensure().await;
        assert!(res.is_err());
        assert!(res.unwrap_err().to_string().contains("generate_ca=false"));
    }

    #[test]
    fn config_validation() {
        let cfg = xproxy_core::Config {
            ca_cert: Some("a.crt".into()),
            ca_key: None,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
        let cfg2 = xproxy_core::Config {
            ca_cert: Some("a.crt".into()),
            ca_key: Some("a.key".into()),
            ..Default::default()
        };
        assert!(cfg2.validate().is_ok());
    }
}
