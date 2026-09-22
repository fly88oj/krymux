//! TLS 1.3 transport for the tunnel: rustls with Ed25519 self-signed
//! certificates on both sides.
//!
//! - Server side: requires a client certificate (any issuer — authorization
//!   happens by fingerprint after the handshake) and the `krymux` ALPN.
//! - Client side: presents its identity, skips CA validation, and pins the
//!   server fingerprint after the handshake (same policy as the Node
//!   implementation).

use crate::keys::LoadedIdentity;
use anyhow::{Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as TlsError, ServerConfig, SignatureScheme,
};
use std::sync::Arc;
use tokio_rustls::TlsAcceptor as Acceptor;
use tokio_rustls::TlsConnector as Connector;

/// The ALPN protocol identifier required on every krymux TLS connection.
pub const ALPN: &[u8] = b"krymux";

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    #[cfg(feature = "pq")]
    return Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    #[cfg(not(feature = "pq"))]
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Accept any presented client certificate; whitelist enforcement happens after
/// the handshake via peer_certificates() (fail closed on resumed/no-cert).
#[derive(Debug)]
struct AnyClientCert(Arc<rustls::crypto::CryptoProvider>);

impl ClientCertVerifier for AnyClientCert {
    // must be false: browsers cannot present TLS client certs, and with the
    // rustls default (true) every cert-less connection is killed inside the
    // handshake — the whole WebSocket branch would be unreachable
    fn client_auth_mandatory(&self) -> bool {
        false
    }

    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, TlsError> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Skip all server-cert validation; we pin the fingerprint ourselves.
#[derive(Debug)]
struct NoServerVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoServerVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Builds the TLS 1.3 acceptor for the server side of the tunnel.
pub fn server_acceptor(identity: &LoadedIdentity) -> Result<Acceptor> {
    let provider = provider();
    let mut cfg = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("tls13 server builder")?
        .with_client_cert_verifier(Arc::new(AnyClientCert(provider)))
        .with_single_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
        .context("server certificate")?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Acceptor::from(Arc::new(cfg)))
}

/// Builds the TLS 1.3 connector for the client side of the tunnel.
pub fn client_connector(identity: &LoadedIdentity) -> Result<Connector> {
    let provider = provider();
    let mut cfg = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("tls13 client builder")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoServerVerify(provider)))
        .with_client_auth_cert(
            vec![identity.cert_der.clone()],
            identity.key_der.clone_key(),
        )
        .context("client certificate")?;
    cfg.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Connector::from(Arc::new(cfg)))
}

/// Verify the pinned fingerprint of the peer's certificate after handshake.
pub fn peer_fingerprint(peer_certs: Option<&[CertificateDer<'_>]>) -> Result<Option<String>> {
    let Some(certs) = peer_certs else {
        return Ok(None);
    };
    let Some(first) = certs.first() else {
        return Ok(None);
    };
    crate::keys::fingerprint_of_cert(first.as_ref()).map(Some)
}
