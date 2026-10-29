//! Trojan client: TLS, then `hex(sha224(password)) CRLF CMD ATYP ADDR PORT CRLF payload`.

use std::sync::Arc;

use anyhow::{anyhow, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha224};
use tokio::io::AsyncWriteExt;
use tokio_rustls::TlsConnector;

use crate::udp::{over_stream, Framing, UdpPipe};
use crate::transport::Transport;
use crate::util::{BoxStream, Target};

/// Accepts any certificate; only used with `skip-cert-verify=true`.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub struct TrojanServer {
    hash: String,
    transport: Transport,
}

/// TLS 1.3-only client config for QUIC-based protocols, with the given ALPN.
pub fn quic_tls_config(skip_cert_verify: bool, alpn: &[u8]) -> Result<ClientConfig> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone()).with_protocol_versions(&[&rustls::version::TLS13])?;
    let mut config = if skip_cert_verify {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    } else {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = vec![alpn.to_vec()];
    Ok(config)
}

/// TLS client setup shared by Trojan and VLESS: connector plus the SNI to send.
pub fn tls_client(server: &str, sni: Option<String>, skip_cert_verify: bool) -> Result<(TlsConnector, ServerName<'static>)> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone()).with_safe_default_protocol_versions()?;
    let config = if skip_cert_verify {
        builder.dangerous().with_custom_certificate_verifier(Arc::new(NoVerify(provider))).with_no_client_auth()
    } else {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    let sni_name = sni.unwrap_or_else(|| server.to_string());
    let sni = ServerName::try_from(sni_name.clone()).map_err(|_| anyhow!("invalid sni {sni_name:?}"))?;
    Ok((TlsConnector::from(Arc::new(config)), sni))
}

impl TrojanServer {
    /// `transport` should have TLS enabled; Trojan has no encryption of its own.
    pub fn new(transport: Transport, password: &str) -> Self {
        TrojanServer { hash: hex::encode(Sha224::digest(password.as_bytes())), transport }
    }

    pub async fn connect(&self, target: &Target) -> Result<BoxStream> {
        self.connect_cmd(target, 1).await
    }

    /// UDP ASSOCIATE (cmd 3): every packet is `ATYP addr port len CRLF payload`.
    pub async fn open_udp(&self, target: &Target) -> Result<UdpPipe> {
        Ok(over_stream(self.connect_cmd(target, 3).await?, Framing::Trojan(target.clone())))
    }

    async fn connect_cmd(&self, target: &Target, cmd: u8) -> Result<BoxStream> {
        let mut stream = self.transport.connect().await?;
        let mut req = Vec::with_capacity(64);
        req.extend_from_slice(self.hash.as_bytes());
        req.extend_from_slice(b"\r\n");
        req.push(cmd);
        target.write_socks_addr(&mut req)?;
        req.extend_from_slice(b"\r\n");
        stream.write_all(&req).await?;
        stream.flush().await?;
        Ok(stream)
    }
}
