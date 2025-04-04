use std::io;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};

use std::error::Error as StdError;
use std::sync::Arc;

use argh::FromArgs;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, CertificateRevocationListDer};
use rustls::RootCertStore;
use rustls::server::WebPkiClientVerifier;
use rustls::AttestationMode;
use tokio::io::{copy, sink, split, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::{rustls, TlsAcceptor};

/// Tokio Rustls server example
#[derive(FromArgs)]
struct Options {
    /// bind addr
    #[argh(positional)]
    addr: String,

    /// cert file
    #[argh(option, short = 'c')]
    cert: PathBuf,

    /// key file
    #[argh(option, short = 'k')]
    key: PathBuf,

    /// client authentication
    #[argh(option)]
    client_auth: Option<PathBuf>,

    /// client authentication -- check for revocation and expiration
    #[argh(option)]
    client_revoke: Option<String>,

    /// echo mode
    #[argh(switch, short = 'e')]
    echo_mode: bool,

    /// enable attested TLS
    /// "disabled" => Ok(AttestationMode::Disabled),
    /// "request" => Ok(AttestationMode::Request): server runs in an enclave and can provide evidence
    /// "proposal" => Ok(AttestationMode::Proposal): server require client to provide evidence
    /// "mutual" => Ok(AttestationMode::RequestProposal): both party must provide evidence
    #[argh(option, short = 'a')]
    attested: AttestationMode,

    /// enable verbose logging
    #[argh(switch, short = 'v')]
    verbose: bool,
}

impl Options {
    /// Helper method to parse `client_revok` into a `Vec<PathBuf>`.
    fn parse_client_revoke(&self) -> Option<Vec<PathBuf>> {
        self.client_revoke.as_ref().map(|input| {
            input
                .split(',') // Split the input string by commas
                .map(|s| PathBuf::from(s.trim())) // Convert each part into a PathBuf
                .collect()
        })
    }
}


fn load_certs(filename: &PathBuf) -> Vec<CertificateDer<'static>> {
    CertificateDer::pem_file_iter(filename)
        .expect("cannot open certificate file")
        .map(|result| result.unwrap())
        .collect()
}

fn load_crls(
    filenames: impl Iterator<Item = impl AsRef<Path>>,
) -> Vec<CertificateRevocationListDer<'static>> {
    filenames
        .map(|filename| {
            CertificateRevocationListDer::from_pem_file(filename).expect("cannot read CRL file")
        })
        .collect()
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError + Send + Sync + 'static>> {
    
    // Parsing commandline arguments and make configuration
    
    let options: Options = argh::from_env();

    let addr = options
        .addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::AddrNotAvailable))?;
    let certs = CertificateDer::pem_file_iter(&options.cert)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(&options.key)?;
    let flag_echo = options.echo_mode;

    if options.verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    // Request Client certificate for mutual authentication
    let client_auth =  if let Some(client_auth) = &options.client_auth {
        let certs = load_certs(client_auth);
        let mut client_auth_roots = RootCertStore::empty();
        for cert in certs {
            client_auth_roots.add(cert).unwrap();
        }
        if let Some(client_revoke) = options.parse_client_revoke(){
            let crls = load_crls(client_revoke.iter());
            WebPkiClientVerifier::builder(client_auth_roots.into())
                .with_crls(crls)
                .build()
                .unwrap()
        } else{
            WebPkiClientVerifier::builder(client_auth_roots.into())
                .build()
                .unwrap()
        }
    } else{
        WebPkiClientVerifier::no_client_auth()
    };
    
    // Fix version to be 1.3
    let mut versions = Vec::new();
    versions.push(&rustls::version::TLS13);

    let config = rustls::ServerConfig::builder_with_protocol_versions(&versions)
        .with_client_cert_verifier(client_auth)
        .with_single_cert(certs, key)?;
    
    // End of making configuration

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind(&addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let acceptor = acceptor.clone();

        let fut = async move {
            let mut stream = acceptor.accept(stream, options.attested).await?;

            if flag_echo {
                let (mut reader, mut writer) = split(stream);
                let n = copy(&mut reader, &mut writer).await?;
                writer.flush().await?;
                println!("Echo: {} - {}", peer_addr, n);
            } else {
                let mut output = sink();
                stream
                    .write_all(
                        &b"HTTP/1.0 200 ok\r\n\
                    Connection: close\r\n\
                    Content-length: 12\r\n\
                    \r\n\
                    Hello Yingchen!"[..],
                    )
                    .await?;
                stream.shutdown().await?;
                copy(&mut stream, &mut output).await?;
                println!("Hello: {}", peer_addr);
            }

            Ok(()) as io::Result<()>
        };

        tokio::spawn(async move {
            if let Err(err) = fut.await {
                eprintln!("{:?}", err);
            }
        });
    }
}


