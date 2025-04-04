use std::error::Error as StdError;
use std::io;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::sync::Arc;

use argh::FromArgs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::AttestationMode;

use tokio::io::{copy, split, stdin as tokio_stdin, stdout as tokio_stdout, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{rustls, TlsConnector};

/// Tokio Rustls client example
#[derive(FromArgs)]
struct Options {
    /// host
    #[argh(positional)]
    host: String,

    /// port
    #[argh(option, short = 'p', default = "443")]
    port: u16,

    /// domain
    #[argh(option, short = 'd')]
    domain: Option<String>,

    /// cafile
    #[argh(option, short = 'c')]
    cafile: Option<PathBuf>,

    /// client ca
    #[argh(option)]
    client_cert: Option<PathBuf>,

    /// client key
    #[argh(option)]
    client_key: Option<PathBuf>,

    /// enable attested TLS
    /// "disabled" => Ok(AttestationMode::Disabled),
    /// "request" => Ok(AttestationMode::Request): ask server to provide evidence
    /// "proposal" => Ok(AttestationMode::Proposal): indicate to server that client can provide evidence
    /// "mutual" => Ok(AttestationMode::RequestProposal): both party must provide evidence
    #[argh(option, short = 'a')]
    attested: AttestationMode,

    /// enable verbose logging
    #[argh(switch, short = 'v')]
    verbose: bool
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {

    // Parsing commandline arguments and make configuration
    let options: Options = argh::from_env();

    if options.verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let addr = (options.host.as_str(), options.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
    let domain = options.domain.unwrap_or(options.host);
    let content = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", domain);

    let mut root_cert_store = rustls::RootCertStore::empty();
    if let Some(cafile) = &options.cafile {
        for cert in CertificateDer::pem_file_iter(cafile)? {
            root_cert_store.add(cert?)?;
        }
    } else {
        root_cert_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    // Client authenticationis optional
    let mut client_cert_key: Option<(Vec<CertificateDer>, PrivateKeyDer)> = None;

    // Only perform client authentication if the client has provided the certificate and key

    if let Some(client_cert) = &options.client_cert {
        let cert = CertificateDer::pem_file_iter(client_cert)?.collect::<Result<Vec<_>, _>>()?;
        if let Some(client_key) = &options.client_key {
            let key = PrivateKeyDer::from_pem_file(client_key)?;
            client_cert_key = Some((cert, key));
        } 
    } 

    // Fix version to be 1.3
    let mut versions = Vec::new();
    versions.push(&rustls::version::TLS13);

    let config_builder = rustls::ClientConfig::builder_with_protocol_versions(&versions)
        .with_root_certificates(root_cert_store);

    let config = if let Some((cert, key)) = client_cert_key {
        config_builder.with_client_auth_cert(cert, key)?
    } else {
        config_builder.with_no_client_auth()
    };

    // End of making configuration

    let connector = TlsConnector::from(Arc::new(config));

    let stream = TcpStream::connect(&addr).await?;

    let (mut stdin, mut stdout) = (tokio_stdin(), tokio_stdout());

    let domain = ServerName::try_from(domain.as_str())?.to_owned();

    /* Attested TLS: Adding extension */
    /* For now: Client propose attestation evidence, also request attestation evidence */

    let mut stream = connector.connect(domain, options.attested, stream).await?;
    
    stream.write_all(content.as_bytes()).await?;

    let (mut reader, mut writer) = split(stream);

    tokio::select! {
        ret = copy(&mut reader, &mut stdout) => {
            ret?;
        },
        ret = copy(&mut stdin, &mut writer) => {
            ret?;
            writer.shutdown().await?
        }
    }

    Ok(())
}
