#![allow(unused_parens)]
use arrayref::array_refs;
use clap::Parser;
use dhcp::Dhcp;
use mio;
use mio::net::UdpSocket;
use openssl::rand;
use qprov::keys::CertificateChain;
use qprov::{Certificate, Encapsulated, SecKeyPair};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use transient_hashmap::TransientHashMap;
use uuid::Uuid;

pub mod dhcp;
pub mod transient_hashmap;

const SOCK: mio::Token = mio::Token(0);
const _TUN: mio::Token = mio::Token(1);

// Q: is it safe to do this?
pub fn iv_from_hello(hello: KeyType) -> u128 {
  let (a, b) = array_refs![&hello.0, 16, 16];
  u128::from_be_bytes(*a) ^ u128::from_be_bytes(*b)
}

pub fn certificate_verificator(_parent: &Certificate, _child: &Certificate) -> bool {
  true
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyType([u8; Self::SIZE]);

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ClientCrypter {
  key: KeyType,
  iv: u128,
  en_seq: u64,
  de_seq: u64,
}

impl ClientCrypter {
  const NONCE_LEN: usize = 16;
  const TAG_LEN: usize = 16;
  pub fn new(key: KeyType, iv: u128) -> Self {
    Self {
      key,
      iv,
      en_seq: 0,
      de_seq: 0,
    }
  }
  pub fn generage_aad(len: usize) -> [u8; std::mem::size_of::<usize>()] {
    len.to_be_bytes()
  }

  pub fn generate_nonce(&mut self) -> [u8; Self::NONCE_LEN] {
    let nonce = (self.iv.wrapping_add(self.en_seq as u128)).to_be_bytes();
    self.en_seq += 1;
    nonce
  }

  pub fn update_nonce(&mut self, nonce: [u8; Self::NONCE_LEN]) -> bool {
    let req_seq = u128::from_be_bytes(nonce).wrapping_sub(self.iv) as u64;
    if req_seq <= self.de_seq {
      return false;
    }
    self.de_seq = req_seq;
    true
  }

  pub fn seal_in_place_append_tag_nonce(&mut self, data: &mut Vec<u8>) {
    let total_len = data.len() + Self::TAG_LEN + Self::NONCE_LEN;
    let mut tag = [0u8; Self::TAG_LEN];
    let nonce = self.generate_nonce();
    let mut encrypted = openssl::symm::encrypt_aead(
      openssl::symm::Cipher::aes_256_gcm(),
      &self.key.0,
      Some(&nonce),
      &Self::generage_aad(total_len),
      &data,
      &mut tag,
    )
    .unwrap();
    assert_eq!(encrypted.len(), data.len());
    encrypted.resize(total_len, 0);
    let len = encrypted.len();
    encrypted[len - Self::TAG_LEN - Self::NONCE_LEN..len - Self::NONCE_LEN].copy_from_slice(&tag);
    encrypted[len - Self::NONCE_LEN..].copy_from_slice(&nonce);
    drop(std::mem::replace(data, encrypted));
  }
  pub fn open_in_place(&self, data: &mut Vec<u8>) -> bool {
    let total_len = data.len();
    if (total_len <= Self::NONCE_LEN + Self::TAG_LEN) {
      return false;
    }
    let nonce = &data[total_len - Self::NONCE_LEN..];
    let tag = &data[total_len - Self::TAG_LEN - Self::NONCE_LEN..total_len - Self::NONCE_LEN];
    let encrypted = &data[..total_len - Self::TAG_LEN - Self::NONCE_LEN];
    let Ok(decrypted) = openssl::symm::decrypt_aead(openssl::symm::Cipher::aes_256_gcm(), &self.key.0, Some(nonce), &Self::generage_aad(total_len), encrypted, tag) else {
      return false;
    };
    drop(std::mem::replace(data, decrypted));
    true
  }
}

impl KeyType {
  const SIZE: usize = 32;
  pub fn zero() -> Self {
    Self([0u8; Self::SIZE])
  }
  pub fn generate() -> Self {
    let mut key = [0u8; Self::SIZE];
    rand::rand_bytes(&mut key).unwrap();
    Self(key)
  }
  pub fn decapsulate(sk: &SecKeyPair, enc: &Encapsulated) -> Self {
    let plain = sk.decapsulate(&enc, Self::SIZE);
    let res = unsafe { *(plain.as_bytes().as_ptr() as *const [_; Self::SIZE]) };
    Self(res)
  }
}
impl std::ops::BitXor<Self> for KeyType {
  type Output = Self;
  fn bitxor(self, rhs: Self) -> Self::Output {
    let mut output = [0u8; Self::SIZE];
    for (out, (l, r)) in output
      .iter_mut()
      .zip(self.0.into_iter().zip(rhs.0.into_iter()))
    {
      *out = l ^ r;
    }
    Self(output)
  }
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
    hash: KeyType,
    server_hello: KeyType,
    derived_key: KeyType,
  },
}

#[derive(Serialize, Deserialize)]
struct HelloMessage {
  chain: CertificateChain,
  random: KeyType,
}

#[derive(Serialize, Deserialize)]
enum DecryptedMessage {
  Ready { hash: KeyType },
  Welcome { ip: Ipv4Addr },
  IpPacket(Vec<u8>),
}

impl DecryptedMessage {
  pub fn encrypt(&self, crypter: &mut ClientCrypter) -> PlainMessage {
    let mut data = bincode::serialize(&self).unwrap();
    crypter.seal_in_place_append_tag_nonce(&mut data);
    PlainMessage::Encrypted(EncryptedMessage(data))
  }
}

#[derive(Debug, Serialize, Deserialize)]
struct EncryptedMessage(Vec<u8>);

impl EncryptedMessage {
  pub fn decrypt(mut self, crypter: &mut ClientCrypter) -> Option<DecryptedMessage> {
    if !crypter.open_in_place(&mut self.0) {
      return None;
    }
    bincode::deserialize(&self.0).ok()
  }
}

#[derive(Serialize, Deserialize)]
enum PlainMessage {
  Hello(HelloMessage),
  Premaster(Encapsulated),
  Ready(EncryptedMessage),
  Encrypted(EncryptedMessage),
}

struct AppState {
  ca: qprov::Certificate,
  sk: qprov::SecKeyPair,
  cert: qprov::keys::CertificateChain,
  socket: UdpSocket,
  potential: TransientHashMap<SocketAddr, PotentianClient>,
  dhcp: Dhcp,
  clients: TransientHashMap<SocketAddr, Uuid>,
  clients_map: HashMap<Uuid, Client>,
  poll: mio::Poll,
  buffer: Box<[u8; 0xffff]>,
}

struct App {
  events: mio::Events,
  state: AppState,
}

fn compare_hashes(_lhs: KeyType, _rhs: KeyType) -> bool {
  true
}

impl App {
  pub fn new() -> Self {
    let args = Cli::parse();
    let file = File::open(args.secret_key_file).expect("Failed to open secret key file");
    let sk: qprov::SecKeyPair =
      bincode::deserialize_from(file).expect("Failed to read secret keys from file");
    let file = File::open(args.certificate_file).expect("Failed to open certificate file");
    let cert: qprov::keys::CertificateChain =
      bincode::deserialize_from(file).expect("Failed to read certificate from file");
    let file = File::open(args.ca_cert_file).expect("Failed to open ca certificate file");
    let ca: qprov::Certificate =
      bincode::deserialize_from(file).expect("Failed to read ca certificate from file");

    let mut socket = UdpSocket::bind(args.bind_address).expect("Failed to bind to address");
    let dhcp = Dhcp::default();
    let potential = TransientHashMap::new(Duration::from_millis(100));
    let poll = mio::Poll::new().unwrap();
    let registry = poll.registry();
    registry
      .register(&mut socket, SOCK, mio::Interest::READABLE)
      .expect("Failed to register socket");
    let events = mio::Events::with_capacity(1024);

    let buffer: Box<[u8; 0xffff]> = boxed_array::from_default();

    let clients = TransientHashMap::new(Duration::from_secs(1));
    let clients_map = Default::default();
    Self {
      events,
      state: AppState {
        ca,
        sk,
        cert,
        socket,
        dhcp,
        potential,
        poll,
        buffer,
        clients,
        clients_map,
      },
    }
  }
  pub fn run(&mut self) {
    for (_, client) in self.state.clients.prune() {
      let client = self.state.clients_map.remove(&client).unwrap();
      self
        .state
        .dhcp
        .free(client.vpn_ip)
        .expect("Contained invalid address");
    }
    drop(self.state.poll.poll(&mut self.events, None));

    for event in &self.events {
      match event.token() {
        SOCK if event.is_readable() => drop(self.state.handle_socket_event()),
        _ => {}
      }
    }
  }
}

impl AppState {
  pub fn handle_socket_event(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let (len, addr) = self.socket.recv_from(self.buffer.as_mut_slice())?;
    let message: PlainMessage = bincode::deserialize(&self.buffer[..len])?;
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
        let total_len = self.buffer.len();
        let mut slice = self.buffer.as_mut_slice();
        bincode::serialize_into(&mut slice, &server_hello)?;
        let serialized_server_hello_len = total_len - slice.len();
        let serialized_server_hello = &self.buffer[..serialized_server_hello_len];
        self.socket.send_to(serialized_server_hello, addr)?;
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
        let premaster = KeyType::decapsulate(&self.sk, &encapsulated);
        let derived_key = client_hello.random ^ server_hello.random ^ premaster;
        let hash = KeyType::zero(); // TODO: compute hashes

        let total_len = self.buffer.len();
        let mut slice = self.buffer.as_mut_slice();
        let mut crypter = ClientCrypter::new(derived_key, iv_from_hello(client_hello.random));
        let encrypted = DecryptedMessage::Ready { hash }.encrypt(&mut crypter);
        bincode::serialize_into(&mut slice, &encrypted)?;
        let len = total_len - slice.len();

        self.socket.send_to(&self.buffer[0..len], addr)?;
        let server_hello = server_hello.random;
        drop(std::mem::replace(
          potential,
          PotentianClient::AwaitReady {
            hash,
            server_hello,
            derived_key,
          }, // TODO: save different hash
        ));
      }
      PlainMessage::Ready(data) => {
        let potential = self.potential.remove(&addr).ok_or(std::io::Error::new(
          ErrorKind::NotFound,
          "Potential client not found",
        ))?;
        let PotentianClient::AwaitReady { hash: expected_hash, server_hello, derived_key } = potential else {
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
        if !compare_hashes(expected_hash, hash) {
          return Err(Box::new(std::io::Error::new(
            ErrorKind::InvalidInput,
            "Hashes did not match",
          )));
        }

        let id = Uuid::new_v4();
        self.clients.insert(addr.clone(), id);
        let ip = self.dhcp.new_client(id)?;
        self.clients_map.remove(&id);
        let client = self.clients_map.entry(id).or_insert(Client {
          crypter,
          socket_addr: addr,
          vpn_ip: ip,
        });
        let total_len = self.buffer.len();
        let mut slice = self.buffer.as_mut_slice();
        let encrypted = DecryptedMessage::Welcome { ip }.encrypt(&mut client.crypter);
        bincode::serialize_into(&mut slice, &encrypted)?;
        let len = total_len - slice.len();

        self.socket.send_to(&self.buffer[0..len], addr)?;
      }
      PlainMessage::Encrypted(data) => {
        let client = self
          .clients
          .get(&addr)
          .and_then(|client| self.clients_map.get_mut(client))
          .ok_or(std::io::Error::new(ErrorKind::NotFound, "Client not found"))?;
        let decrypted = data
          .decrypt(&mut client.crypter)
          .ok_or(std::io::Error::new(
            ErrorKind::InvalidInput,
            "Failed to decrypt message",
          ))?;
        let DecryptedMessage::IpPacket(data) = &decrypted else {
          return Err(Box::new(std::io::Error::new(ErrorKind::InvalidInput, "Invalid input for state registered client")));
        };
        let destination = parse_packet(data).ok_or(std::io::Error::new(
          ErrorKind::InvalidInput,
          "Failed to get recipent from packet",
        ))?;
        let recipent = self
          .clients_map
          .get_mut(&self.dhcp.get(destination)?)
          .ok_or(std::io::Error::new(
            ErrorKind::NotFound,
            "Recipent not found in pool",
          ))?;
        let encrypted = decrypted.encrypt(&mut recipent.crypter);

        let total_len = self.buffer.len();
        let mut slice = self.buffer.as_mut_slice();
        bincode::serialize_into(&mut slice, &encrypted)?;
        let len = total_len - slice.len();

        self
          .socket
          .send_to(&self.buffer[0..len], recipent.socket_addr)?;
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

fn parse_packet(data: &[u8]) -> Option<Ipv4Addr> {
  let packet = etherparse::SlicedPacket::from_ip(data).unwrap();
  let ip = packet.ip?;
  match ip {
    etherparse::InternetSlice::Ipv4(header, _exts) => {
      let header = header.to_header();
      println!("packet header: {header:?}");
      return Some(Ipv4Addr::from(header.destination));
    }
    etherparse::InternetSlice::Ipv6(_header, _exts) => {
      // let header = header.to_header();
      // println!("packet header: {header:?}");
    }
  }
  None
}

#[derive(clap::Parser)]
struct Cli {
  #[arg(short, long, default_value_t = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 9011)))]
  bind_address: SocketAddr,
  #[arg(short, long, default_value_t = ("server.key".to_owned()))]
  secret_key_file: String,
  #[arg(short, long, default_value_t = ("server.crt".to_owned()))]
  certificate_file: String,
  #[arg(short, long, default_value_t = ("ca.crt".to_owned()))]
  ca_cert_file: String,
}
