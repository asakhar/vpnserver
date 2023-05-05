#![allow(unused_parens)]
use clap::Parser;
use dhcp::Dhcp;
use qprov::Certificate;
use std::io::{ErrorKind, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use transient_hashmap::TransientHashMap;
use uuid::Uuid;
use vpnmessaging::mio::net::{TcpListener, UdpSocket};
use vpnmessaging::qprov::keys::FileSerialize;
use vpnmessaging::qprov::CertificateChain;
use vpnmessaging::{
  compare_hashes, iv_from_hello, mio, BufferedTcpStream, DecryptedHandshakeMessage, VpnError,
  VpnResult,
};
use vpnmessaging::{qprov, MessagePart};
use vpnmessaging::{
  send_unreliable_to, ClientCrypter, DecryptedMessage, HandshakeMessage, HelloMessage, IdPair,
  KeyType, MessagePartsCollection,
};

pub mod dhcp;
pub mod transient_hashmap;

const UDP_SOCK: mio::Token = mio::Token(0);
const TCP_SOCK: mio::Token = mio::Token(1);
const TUN: mio::Token = mio::Token(2);

pub fn certificate_verificator(_parent: &Certificate, _child: &Certificate) -> bool {
  true
}

struct Client {
  crypter: ClientCrypter,
  socket_addr: SocketAddr,
  vpn_ip: Ipv4Addr,
}

enum PotentianClient {
  AwaitHello,
  AwaitPremaster {
    client_chain: CertificateChain,
    client_random: KeyType,
    server_random: KeyType,
  },
  AwaitReady {
    server_random: KeyType,
    derived_key: KeyType,
  },
}

const BUF_SIZE: usize = 0x10000;
fn next(current: &mut mio::Token) -> mio::Token {
  let next = current.0;
  if next == usize::MAX {
    current.0 = TUN.0 + 1;
  } else {
    current.0 += 1;
  }
  mio::Token(next)
}

struct AppState {
  ca: qprov::Certificate,
  sk: qprov::SecKeyPair,
  unique_token: mio::Token,
  cert: Vec<u8>,
  udp_socket: UdpSocket,
  tcp_socket: TcpListener,
  tun_sender: mio_tun::TunSender,
  dhcp: Dhcp,
  clients: TransientHashMap<Uuid, Client>,
  messages: TransientHashMap<IdPair, MessagePartsCollection>,
  connections: TransientHashMap<mio::Token, (BufferedTcpStream, PotentianClient)>,
  poll: mio::Poll,
  buffer: Box<[u8; BUF_SIZE]>,
}

struct App {
  tun: mio_tun::Tun,
  events: mio::Events,
  state: AppState,
}

impl App {
  pub fn new() -> Self {
    let args = Cli::parse();
    let sk = qprov::SecKeyPair::from_file(&args.secret_key_file)
      .expect("Failed to read secret keys from file");
    let cert = qprov::CertificateChain::from_file(&args.certificate_chain_file)
      .expect("Failed to read certificate from file");
    let cert = bincode::serialize(&cert).unwrap();
    let ca = qprov::Certificate::from_file(&args.ca_cert_file)
      .expect("Failed to read ca certificate from file");

    let mut udp_socket = UdpSocket::bind(args.udp_bind_address).expect("Failed to bind to address");
    let mut tcp_socket =
      TcpListener::bind(args.tcp_bind_address).expect("Failed to bind to address");
    let dhcp = Dhcp::default();
    let mut tun = mio_tun::Tun::new_with_path(
      "./wintun.dll",
      "DemoServer",
      "ExampleServer",
      dhcp.get_self(),
      dhcp.get_net_mask_suffix(),
    )
    .unwrap();
    let connections = TransientHashMap::new(Duration::from_secs(60 * 60));
    let poll = mio::Poll::new().unwrap();
    let registry = poll.registry();
    registry
      .register(&mut udp_socket, UDP_SOCK, mio::Interest::READABLE)
      .expect("Failed to register udp socket");
    registry
      .register(&mut tcp_socket, TCP_SOCK, mio::Interest::READABLE)
      .expect("Failed to register tcp socket");
    registry
      .register(&mut tun, TUN, mio::Interest::READABLE)
      .expect("Failed to register tun");
    let events = mio::Events::with_capacity(1024);

    let buffer: Box<[u8; BUF_SIZE]> = boxed_array::from_default();

    let clients = TransientHashMap::new(Duration::from_secs(60 * 60));
    let messages = TransientHashMap::new(Duration::from_secs(60 * 60));
    let tun_sender = tun.sender();
    let unique_token = mio::Token(TUN.0 + 1);
    Self {
      events,
      tun,
      state: AppState {
        ca,
        sk,
        cert,
        udp_socket,
        tcp_socket,
        tun_sender,
        dhcp,
        unique_token,
        connections,
        poll,
        buffer,
        clients,
        messages,
      },
    }
  }
  pub fn run(&mut self) {
    for (id, client) in self.state.clients.prune() {
      println!("Pruned client: {id} ({})", client.socket_addr);
      self
        .state
        .dhcp
        .free(client.vpn_ip)
        .expect("Contained invalid address");
    }
    for (IdPair(addr, id), _) in self.state.messages.prune() {
      println!("Pruned {}:{}", addr, id);
    }
    for (token, (stream, _)) in self.state.connections.prune() {
      let mut stream = stream.into_inner();
      drop(
        self
          .state
          .poll
          .registry()
          .deregister(&mut stream),
      );
      println!("Pruned potential client {}", token.0);
    }
    self.state.poll.poll(&mut self.events, None).unwrap();

    for event in &self.events {
      match event.token() {
        UDP_SOCK => loop {
          let result = self.state.handle_udp_socket_event();
          if let Err(error) = result {
            if matches!(error, VpnError::WouldBlock) {
              break;
            }
            println!("udp sock error: {:?}", error);
          }
        },
        TCP_SOCK => loop {
          let result = self.state.handle_tcp_socket_event();
          if let Err(error) = result {
            if matches!(error, VpnError::WouldBlock) {
              break;
            }
            println!("tcp sock error: {:?}", error);
          }
        },
        TUN => {
          for packet in self.tun.iter() {
            if let Err(error) = self.state.handle_tun_event(packet) {
              println!("tun error: {error}");
            }
          }
        }
        token => loop {
          let result = self.state.handle_stream_event(token, event);
          if let Ok(true) = result {
            break;
          }
          if let Err(error) = result {
            if matches!(error, VpnError::WouldBlock) {
              break;
            }
            println!("tcp stream error: {:?}", error);
          }
        },
      }
    }
  }
}

impl AppState {
  pub fn handle_tun_event(&mut self, packet: Vec<u8>) -> VpnResult<()> {
    let Some((_, destination)) = parse_packet(&packet) else {return Ok(())};
    if self.dhcp.is_broadcast(destination) {
      return Ok(());
    }
    let Some((recipent_id, recipent)) = self
      .dhcp
      .get(destination)
      .ok()
      .and_then(|recipent_id| self.clients.get_mut(&recipent_id).map(|recipent| (recipent_id, recipent)))  else {return Ok(());};
    let encrypted = DecryptedMessage::IpPacket(packet).encrypt(&mut recipent.crypter, recipent_id);

    send_unreliable_to(
      &mut self.udp_socket,
      recipent.socket_addr,
      encrypted,
      self.buffer.as_mut_slice(),
    )?;
    Ok(())
  }
  pub fn handle_udp_socket_event(&mut self) -> VpnResult<()> {
    let (len, addr) = self.udp_socket.recv_from(self.buffer.as_mut_slice())?;
    let part: MessagePart = bincode::deserialize(&self.buffer[..len])?;
    let id = part.id;
    let messages = self
      .messages
      .entry(IdPair(addr, id))
      .or_insert_with(|| MessagePartsCollection::new(part.total));
    let result_add = messages.add(part)?;
    let Some(message) = result_add else {
      return Ok(());
    };
    drop(self.messages.remove(&IdPair(addr, id)));
    let Some(client) = self.clients.get_mut(&message.get_sender_id()) else {
      return Err(VpnError::NotFound);
    };
    match client.socket_addr {
      SocketAddr::V4(socket_addr)
        if socket_addr.ip().is_unspecified() && socket_addr.port() == 0 =>
      {
        drop(std::mem::replace(&mut client.socket_addr, addr));
      }
      _ => {
        if addr != client.socket_addr {
          println!("Client changed address: {} -> {}", client.socket_addr, addr);
          drop(std::mem::replace(&mut client.socket_addr, addr));
        }
      }
    }
    let Some(decrypted) = message.decrypt(&mut client.crypter) else {
      return Err(VpnError::InvalidData);
    };
    match decrypted {
      DecryptedMessage::IpPacket(packet) => {
        self.tun_sender.send(packet);
      }
      DecryptedMessage::KeepAlive => {
        send_unreliable_to(
          &mut self.udp_socket,
          addr,
          message,
          self.buffer.as_mut_slice(),
        )?;
      }
    }
    Ok(())
  }
  pub fn handle_tcp_socket_event(&mut self) -> VpnResult<()> {
    let (mut stream, addr) = self.tcp_socket.accept()?;
    stream.set_nodelay(true)?;
    println!("Connection from: {addr}");
    let token = next(&mut self.unique_token);
    self.poll.registry().register(
      &mut stream,
      token,
      mio::Interest::READABLE | mio::Interest::WRITABLE,
    )?;
    self
      .connections
      .insert(token, (stream.into(), PotentianClient::AwaitHello));
    Ok(())
  }
  pub fn handle_stream_event(
    &mut self,
    token: mio::Token,
    event: &mio::event::Event,
  ) -> VpnResult<bool> {
    let Some((stream, potential)) = self.connections.get_mut(&token) else {
      return Ok(true);
     };
    if event.is_writable() {
      stream.flush()?;
    }
    if !event.is_readable() {
      return Ok(true);
    }
    let message = stream.read_sized()?;
    let message: HandshakeMessage = bincode::deserialize(&message)?;
    match message {
      HandshakeMessage::Hello(client_hello) => {
        let PotentianClient::AwaitHello = potential else {
          return Err(VpnError::InvalidData);
        };
        let Some(client_chain) = client_hello.chain() else {return Err(VpnError::InvalidData);};
        if !client_chain.verify(&self.ca, certificate_verificator) {
          return Err(VpnError::PermissionDenied);
        }
        let server_hello = HelloMessage::from_serialized(self.cert.clone());
        let message = HandshakeMessage::Hello(server_hello.clone());
        bincode::serialize_into(&mut *stream, &message)?;
        drop(std::mem::replace(
          potential,
          PotentianClient::AwaitPremaster {
            client_chain,
            client_random: client_hello.random,
            server_random: server_hello.random,
          },
        ));
        stream.flush()?;
      }
      HandshakeMessage::Premaster(encapsulated) => {
        let PotentianClient::AwaitPremaster { ref client_chain, client_random, server_random } = *potential else {
          return Err(VpnError::InvalidData);
        };
        let server_premaster = KeyType::decapsulate(&self.sk, &encapsulated);
        let (encapsulated, client_premaster) =
          KeyType::encapsulate(&client_chain.get_target().contents.pub_keys);
        let message = HandshakeMessage::Premaster(encapsulated);

        bincode::serialize_into(&mut *stream, &message)?;
        let derived_key = client_random ^ server_random ^ server_premaster ^ client_premaster;
        drop(std::mem::replace(
          potential,
          PotentianClient::AwaitReady {
            server_random,
            derived_key,
          },
        ));
        stream.flush()?;
      }
      HandshakeMessage::Ready(data) => {
        let PotentianClient::AwaitReady { server_random, derived_key } = *potential else {
          return Err(VpnError::InvalidData);
        };
        let mut crypter = ClientCrypter::new(derived_key, iv_from_hello(server_random));
        let data = data.decrypt(&mut crypter).ok_or(std::io::Error::new(
          ErrorKind::InvalidInput,
          "Failed to decrypt message",
        ))?;
        let DecryptedHandshakeMessage::Ready { hash } = data else {
          return Err(VpnError::InvalidData);
        };
        let expected_hash = KeyType::zero(); // TODO: compute hash
        if !compare_hashes(expected_hash, hash) {
          return Err(VpnError::InvalidData);
        }

        let id = loop {
          let id = Uuid::new_v4();
          if !self.clients.contains_key(&id) {
            break id;
          }
        };
        let ip = self.dhcp.new_client(id)?;

        let client = self.clients.entry(id).or_insert(Client {
          crypter,
          socket_addr: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
          vpn_ip: ip,
        });

        let encrypted = DecryptedHandshakeMessage::Welcome {
          id,
          ip,
          mask: self.dhcp.get_net_mask_suffix(),
        }
        .encrypt(&mut client.crypter);
        bincode::serialize_into(&mut *stream, &encrypted)?;
        stream.flush()?;
        let mut stream = self.connections.remove(&token).unwrap().0.into_inner();
        stream.shutdown(std::net::Shutdown::Both)?;
        self.poll.registry().deregister(&mut stream)?;
        return Ok(true);
      }
    }
    Ok(false)
  }
}

fn main() {
  let mut app = App::new();
  loop {
    app.run();
  }
}

fn parse_packet(data: &[u8]) -> Option<(Ipv4Addr, Ipv4Addr)> {
  let packet = etherparse::SlicedPacket::from_ip(data).unwrap();
  let ip = packet.ip?;
  match ip {
    etherparse::InternetSlice::Ipv4(header, _exts) => {
      let header = header.to_header();
      Some((
        Ipv4Addr::from(header.source),
        Ipv4Addr::from(header.destination),
      ))
    }
    _ => None,
  }
}

#[derive(clap::Parser)]
struct Cli {
  #[arg(short, long, default_value_t = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9011)))]
  udp_bind_address: SocketAddr,
  #[arg(short, long, default_value_t = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9010)))]
  tcp_bind_address: SocketAddr,
  #[arg(short, long, default_value_t = ("keys/server.key".to_owned()))]
  secret_key_file: String,
  #[arg(short = 'e', long, default_value_t = ("keys/server.chn".to_owned()))]
  certificate_chain_file: String,
  #[arg(short, long, default_value_t = ("keys/ca.crt".to_owned()))]
  ca_cert_file: String,
}
