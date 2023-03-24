#![allow(unused_parens)]
use clap::Parser;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

// mod context;
// mod handshake;
mod sized_read_writes;

#[tokio::main]
async fn main() {
  let args = Cli::parse();
  let (sk, pk) = if !std::path::Path::new(&args.secret_key_file).exists() {
    let (pk, sk) = rmce::generate_keypair();
    pk.to_file(&args.public_key_file)
      .expect("Failed to create file for public key");
    sk.to_file(&args.secret_key_file)
      .expect("Failed to create file for secret key");
    (sk, pk)
  } else {
    let sk = rmce::SecretKey::from_file(&args.secret_key_file)
      .expect(&format!("File not found: {}", args.secret_key_file));
    let pk = rmce::PublicKey::from_file(&args.public_key_file)
      .expect(&format!("File not found: {}", args.public_key_file));
    (sk, pk)
  };
  let sk: &'static _ = Box::leak(Box::new(sk));
  let pk: &'static _ = Box::leak(Box::new(pk));

  let listener = TcpListener::bind(&args.bind_address)
    .await
    .expect("Failed to bind to address");

  loop {
    let Ok((socket, addr)) = listener.accept().await else {
      eprintln!("Connection failure");
      continue;
    };
    tokio::spawn(handle_client(socket, addr, &pk, &sk));
  }
}

async fn handle_client(
  mut stream: TcpStream,
  addr: SocketAddr,
  pk: &rmce::PublicKey,
  sk: &rmce::SecretKey,
) {
  println!("Connection from: {addr}");
  if let Err(err) = stream.write_all(pk.as_bytes()).await {
    eprintln!("Error writing to client: {err}");
    return;
  };
  let mut shared_secret_buf = [0u8; rmce::ShareableSecret::SIZE];
  if let Err(err) = stream.read_exact(&mut shared_secret_buf).await {
    eprintln!("Error reading from client: {err}");
    return;
  }
  let shared_secret = rmce::ShareableSecret::from(shared_secret_buf);
  let cipher = openssl::symm::Cipher::aes_256_cbc();
  let plain_secret = shared_secret.open(cipher.key_len(), sk);
  let key = plain_secret.as_bytes();
  let data = b"Some Crypto Text";
  let mut iv = vec![0u8; cipher.iv_len().unwrap()];
  openssl::rand::rand_bytes(&mut iv).unwrap();
  let ciphertext = openssl::symm::encrypt(cipher, key, Some(&iv), data).unwrap();
  if let Err(err) = stream.write_all(&iv.len().to_be_bytes()).await {
    eprintln!("Error writing iv len to client: {err}");
    return;
  }
  if let Err(err) = stream.write_all(&iv).await {
    eprintln!("Error writing iv to client: {err}");
    return;
  }
  if let Err(err) = stream.write_all(&ciphertext.len().to_be_bytes()).await {
    eprintln!("Error writing msg len to client: {err}");
    return;
  }
  if let Err(err) = stream.write_all(&ciphertext).await {
    eprintln!("Error writing msg to client: {err}");
    return;
  }
}

#[derive(clap::Parser)]
struct Cli {
  #[arg(short, long, default_value_t = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9011)))]
  bind_address: SocketAddr,
  #[arg(short, long, default_value_t = ("server.key".to_owned()))]
  secret_key_file: String,
  #[arg(short, long, default_value_t = ("server.cert".to_owned()))]
  public_key_file: String,
}
