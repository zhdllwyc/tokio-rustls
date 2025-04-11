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




// Core abstraction interface: The trait a user will implement to customize their own state machine
// Connection state machine takes in an input, a party state, and the currerent FSM state, and perform transition, and produce output
pub trait ConnectionStateMachine<S> {
    /// Total number of offline states. Return 0 to skip offline stages.
    fn offline_stage_count(&self) -> usize;

    /// Total number of online states
    fn online_stage_count(&self) -> usize;

    /// Given the current FSM state, input, and party state, perform a transition
    fn transition(&mut self, input: &str, state: &mut S, current_mode: ConnectionMode) -> ConnectionStatus;
}


// Enum representing whether we're in offline or online mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionMode {
    Offline(usize), // Current offline stage
    Online(usize),  // Current online stage
}

// Enum representing the result of a state transition
#[derive(Debug, Clone)]
pub enum ConnectionStatus {
    TransitionTo(ConnectionMode),
    Disconnect,
}



// A connection session that runs the state machine
pub struct Connection<T: ConnectionStateMachine<S>, S> {
    state_machine: T,
    mode: ConnectionMode,
    counter: usize,
    pub user_state: S,
}

// Connection works with any types T and S: implementing methods for the Connection struct, which is generic over T (the FSM) and S (the party state).
// T: ConnectionStateMachine is a trait bound: T must implement the ConnectionStateMachine trait for state type S
impl<T: ConnectionStateMachine<S>, S> Connection<T, S> {
    pub fn new(state_machine: T, user_state: S) -> Self {
        let initial_mode = if state_machine.offline_stage_count() == 0 {
            ConnectionMode::Online(0)
        } else {
            ConnectionMode::Offline(0)
        };

        Self {
            state_machine,
            mode: initial_mode,
            counter: 0,
            user_state,
        }
    }

    pub fn handle_input(&mut self, input: &str) -> bool {
        match self.state_machine.transition(input, &mut self.user_state) {
            ConnectionStatus::TransitionTo(new_mode) => {
                self.mode = new_mode;
                true
            }
            ConnectionStatus::Stay => true,
            ConnectionStatus::Disconnect => false,
        }
    }

    pub fn get_mode(&self) -> ConnectionMode {
        self.mode
    }
}


// Example party state
#[derive(Debug)]
struct PartyState {
    pub counter: usize,
}

// Example user implementation for testing
struct ExampleFSM;

impl ConnectionStateMachine<PartyState> for ExampleFSM {
    fn offline_stage_count(&self) -> usize {
        0 // No offline stage
    }

    fn online_stage_count(&self) -> usize {
        6
    }

    fn transition(&mut self, input: &str, state: &mut PartyState, current_mode: ConnectionMode) -> ConnectionStatus {
        match (input, current_mode) {
            ("next", ConnectionMode::Online(stage)) if stage < 5 => {
                state.counter += 1;
                ConnectionStatus::TransitionTo(ConnectionMode::Online(stage + 1))
            }
            ("disconnect", _) => ConnectionStatus::Disconnect,
            _ => ConnectionStatus::Disconnect,
        }
    }
}


async fn handle_client(stream: TcpStream) {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut lines = reader.lines();

    let user_state = PartyState { counter: 0 };
    let mut conn = Connection::new(ExampleFSM, user_state);

    while let Ok(Some(line)) = lines.next_line().await {
        let keep_alive = conn.handle_input(&line);
        let response = format!("Current mode: {:?}\nUser state: {:?}\n", conn.get_mode(), conn.user_state);
        if writer.write_all(response.as_bytes()).await.is_err() {
            break;
        }
        if !keep_alive {
            break;
        }
    }
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


        // tokio::spawn schedules the task onto a worker thread pool managed by the Tokio runtime.
        // It's like a super-efficient thread scheduler: tasks are small, cheap, and cooperative (they yield via .await).
        tokio::spawn(async move {
            // if let Err(err) = fut.await {
            //     eprintln!("{:?}", err);
            // }

            handle_client(stream).await;
        });
    }
}



