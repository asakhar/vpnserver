#![allow(unused_parens)]
use clap::Parser;
use dhcp::Dhcp;
use qprov::Certificate;
use vpnmessaging::qprov::keys::FileSerialize;
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use transient_hashmap::TransientHashMap;
use uuid::Uuid;
use vpnmessaging::mio::net::UdpSocket;
use vpnmessaging::qprov;
use vpnmessaging::{
  compare_hashes, iv_from_hello, send_ack_to, send_guaranteed_to, send_unreliable_to,
  ClientCrypter, DecryptedMessage, HelloMessage, IdPair, KeyType, MessagePartsCollection,
  PlainMessage, TransmissionMessage,
};
use vpnmessaging::{mio, send_fin_to};

pub mod dhcp;
pub mod transient_hashmap;

const SOCK: mio::Token = mio::Token(0);
const TUN: mio::Token = mio::Token(1);

pub fn certificate_verificator(_parent: &Certificate, _child: &Certificate) -> bool {
  true
}

struct Client {
  crypter: ClientCrypter,
  socket_addr: SocketAddr,
  vpn_ip: Ipv4Addr,
}

enum PotentianClient {
  AwaitPremaster {
    client_hello: HelloMessage,
    server_hello: HelloMessage,
  },
  AwaitReady {
    server_hello: KeyType,
    derived_key: KeyType,
  },
}

const BUF_SIZE: usize = 0x10000;

struct AppState {
  ca: qprov::Certificate,
  sk: qprov::SecKeyPair,
  cert: qprov::keys::CertificateChain,
  socket: UdpSocket,
  tun_sender: mio_tun::TunSender,
  potential: TransientHashMap<SocketAddr, PotentianClient>,
  dhcp: Dhcp,
  clients: TransientHashMap<SocketAddr, Uuid>,
  clients_map: HashMap<Uuid, Client>,
  messages: TransientHashMap<IdPair, MessagePartsCollection>,
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
    let ca = qprov::Certificate::from_file(&args.ca_cert_file)
      .expect("Failed to read ca certificate from file");

    let mut socket = UdpSocket::bind(args.bind_address).expect("Failed to bind to address");
    let dhcp = Dhcp::default();
    let mut tun = mio_tun::Tun::new_with_path(
      "./wintun.dll",
      "DemoServer",
      "ExampleServer",
      dhcp.get_self(),
      dhcp.get_net_mask_suffix(),
    )
    .unwrap();
    let potential = TransientHashMap::new(Duration::from_millis(1000));
    let poll = mio::Poll::new().unwrap();
    let registry = poll.registry();
    registry
      .register(&mut socket, SOCK, mio::Interest::READABLE)
      .expect("Failed to register socket");
    registry
      .register(&mut tun, TUN, mio::Interest::READABLE)
      .expect("Failed to register tun");
    let events = mio::Events::with_capacity(1024);

    let buffer: Box<[u8; BUF_SIZE]> = boxed_array::from_default();

    let clients = TransientHashMap::new(Duration::from_secs(20));
    let clients_map = Default::default();
    let messages = TransientHashMap::new(Duration::from_secs(20));
    let tun_sender = tun.sender();
    Self {
      events,
      tun,
      state: AppState {
        ca,
        sk,
        cert,
        socket,
        tun_sender,
        dhcp,
        potential,
        poll,
        buffer,
        clients,
        clients_map,
        messages,
      },
    }
  }
  pub fn run(&mut self) {
    for (addr, client) in self.state.clients.prune() {
      println!("Pruned client: {addr}");
      let client = self.state.clients_map.remove(&client).unwrap();
      self
        .state
        .dhcp
        .free(client.vpn_ip)
        .expect("Contained invalid address");
    }
    for (IdPair(addr, id), _) in self.state.messages.prune() {
      println!("Pruned {}:{}", addr, id);
    }
    for (potential, _) in self.state.potential.prune() {
      println!("Pruned potential client {}", potential);
    }
    self.state.poll.poll(&mut self.events, None).unwrap();

    for event in &self.events {
      match event.token() {
        SOCK => loop {
          let result = self.state.handle_socket_event();
          if let Err(error) = result {
            if let Some(error) = error.downcast_ref::<std::io::Error>() {
              if matches!(error.kind(), ErrorKind::WouldBlock) {
                break;
              }
            }
            println!("sock error: {:?}", error);
          }
        },
        TUN => {
          for packet in self.tun.iter() {
            if let Err(error) = self.state.handle_tun_event(packet) {
              println!("tun error: {error}");
            }
          }
        }
        _ => {}
      }
    }
    self.events.clear();
  }
}

impl AppState {
  pub fn handle_tun_event(&mut self, packet: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
    let Some((_, destination)) = parse_packet(&packet) else {return Ok(())};
    if self.dhcp.is_broadcast(destination) {
      return Ok(());
    }
    let Some(recipent) = self
      .dhcp
      .get(destination)
      .ok()
      .and_then(|recipent_id| self.clients_map.get_mut(&recipent_id))  else {return Ok(());};
    let encrypted = DecryptedMessage::IpPacket(packet).encrypt(&mut recipent.crypter);

    send_unreliable_to(
      &mut self.socket,
      recipent.socket_addr,
      encrypted,
      self.buffer.as_mut_slice(),
    )?;
    Ok(())
  }
  pub fn handle_socket_event(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let (len, addr) = self.socket.recv_from(self.buffer.as_mut_slice())?;
    let message: TransmissionMessage = bincode::deserialize(&self.buffer[..len])?;
    let TransmissionMessage::Part(part) = message else {
      return Ok(());
    };
    let id = part.id;
    let requires_ack = part.requires_ack;
    let messages = self
      .messages
      .entry(IdPair(addr, id))
      .or_insert_with(|| MessagePartsCollection::new(part.total));
    let result_add = messages.add(part)?;
    if requires_ack {
      let first_unrecv = messages.first_unreceived();
      if first_unrecv != 0 {
        send_ack_to(
          &mut self.socket,
          addr,
          id,
          first_unrecv - 1,
          self.buffer.as_mut_slice(),
        )?;
      }
    };
    let Some(message) = result_add else {
      return Ok(());
    };
    if requires_ack {
      send_fin_to(&mut self.socket, addr, id, self.buffer.as_mut_slice())?;
    }
    drop(self.messages.remove(&IdPair(addr, id)));
    match message {
      PlainMessage::Hello(client_hello) => {
        if !client_hello.chain.verify(&self.ca, certificate_verificator) {
          return Err(Box::new(std::io::Error::new(
            ErrorKind::InvalidInput,
            "Failed to authorize clients certificate",
          )));
        }
        let random = KeyType::generate();
        let server_hello = HelloMessage {
          chain: self.cert.clone(),
          random,
        };
        let message = PlainMessage::Hello(server_hello.clone());
        send_guaranteed_to(
          &mut self.socket,
          addr,
          message,
          self.buffer.as_mut_slice(),
          Some(Duration::from_millis(2000)),
        )?;
        let potential = PotentianClient::AwaitPremaster {
          client_hello,
          server_hello,
        };
        self.potential.insert(addr, potential);
      }
      PlainMessage::Premaster(encapsulated) => {
        let potential = self.potential.get_mut(&addr).ok_or(std::io::Error::new(
          ErrorKind::NotFound,
          "Potential client not found",
        ))?;
        let PotentianClient::AwaitPremaster { client_hello, server_hello } = potential else {
          return Err(Box::new(std::io::Error::new(ErrorKind::InvalidInput, "Invalid input for state await premaster")));
        };
        let server_premaster = KeyType::decapsulate(&self.sk, &encapsulated);
        let (encapsulated, client_premaster) =
          KeyType::encapsulate(&client_hello.chain.get_target().contents.pub_keys);
        let message = PlainMessage::Premaster(encapsulated);
        send_guaranteed_to(
          &mut self.socket,
          addr,
          message,
          self.buffer.as_mut_slice(),
          Some(Duration::from_millis(500)),
        )?;

        let derived_key =
          client_hello.random ^ server_hello.random ^ server_premaster ^ client_premaster;

        let server_hello = server_hello.random;
        drop(std::mem::replace(
          potential,
          PotentianClient::AwaitReady {
            server_hello,
            derived_key,
          },
        ));
      }
      PlainMessage::Ready(data) => {
        let potential = self.potential.remove(&addr).ok_or(std::io::Error::new(
          ErrorKind::NotFound,
          "Potential client not found",
        ))?;
        let PotentianClient::AwaitReady { server_hello, derived_key } = potential else {
          return Err(Box::new(std::io::Error::new(ErrorKind::InvalidInput, "Invalid input for state await ready")));
        };
        let mut crypter = ClientCrypter::new(derived_key, iv_from_hello(server_hello));
        let data = data.decrypt(&mut crypter).ok_or(std::io::Error::new(
          ErrorKind::InvalidInput,
          "Failed to decrypt message",
        ))?;
        let DecryptedMessage::Ready { hash } = data else {
          return Err(Box::new(std::io::Error::new(ErrorKind::InvalidInput, "Invalid input for state await ready")));
        };
        let expected_hash = KeyType::zero(); // TODO: compute hash
        if !compare_hashes(expected_hash, hash) {
          return Err(Box::new(std::io::Error::new(
            ErrorKind::InvalidInput,
            "Hashes did not match",
          )));
        }

        let id = Uuid::new_v4();
        self.clients.insert(addr.clone(), id);
        let ip = self.dhcp.new_client(id)?;
        if let Some(old) = self.clients_map.remove(&id) {
          drop(self.dhcp.free(old.vpn_ip));
        }

        let client = self.clients_map.entry(id).or_insert(Client {
          crypter,
          socket_addr: addr,
          vpn_ip: ip,
        });

        let encrypted = DecryptedMessage::Welcome {
          ip,
          mask: self.dhcp.get_net_mask_suffix(),
        }
        .encrypt(&mut client.crypter);

        send_guaranteed_to(
          &mut self.socket,
          addr,
          encrypted,
          self.buffer.as_mut_slice(),
          Some(Duration::from_millis(500)),
        )?;
      }
      PlainMessage::Encrypted(data) => {
        let client = self
          .clients
          .get(&addr)
          .and_then(|client| self.clients_map.get_mut(client))
          .ok_or(std::io::Error::new(
            ErrorKind::NotFound,
            format!("Client not found: {}", addr),
          ))?;
        let decrypted = data
          .decrypt(&mut client.crypter)
          .ok_or(std::io::Error::new(
            ErrorKind::InvalidInput,
            "Failed to decrypt message",
          ))?;
        if matches!(decrypted, DecryptedMessage::KeepAlive) {
          let encrypted = decrypted.encrypt(&mut client.crypter);
          return Ok(send_unreliable_to(
            &self.socket,
            addr,
            encrypted,
            self.buffer.as_mut_slice(),
          )?);
        }
        let DecryptedMessage::IpPacket(data) = decrypted else {
          return Err(Box::new(std::io::Error::new(ErrorKind::InvalidInput, "Invalid input for state registered client")));
        };
        self.tun_sender.send(data);
      }
    }
    Ok(())
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
  bind_address: SocketAddr,
  #[arg(short, long, default_value_t = ("keys/server.key".to_owned()))]
  secret_key_file: String,
  #[arg(short = 'e', long, default_value_t = ("keys/server.chn".to_owned()))]
  certificate_chain_file: String,
  #[arg(short, long, default_value_t = ("keys/ca.crt".to_owned()))]
  ca_cert_file: String,
}
