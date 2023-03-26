#![allow(unused_parens)]
use clap::Parser;
use dhcp::Dhcp;
use qprov::serialization::Deserializable;
use std::fs::File;
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::{mpsc, Arc};

use qprov::sized_read_writes::{ReadSizedExt, WriteSizedExt};
use qprov::{PqsChannel, PqsContext};

mod dhcp;

fn main() {
  let args = Cli::parse();
  let mut file = File::open(args.secret_key_file).expect("Failed to open secret key file");
  let sk = qprov::SecKeyPair::deserialize(&mut file).expect("Failed to read secret keys from file");
  let mut file = File::open(args.certificate_file).expect("Failed to open certificate file");
  let cert =
    qprov::Certificate::deserialize(&mut file).expect("Failed to read certificate from file");
  let context: &'static _ = Box::leak(Box::new(PqsContext::server(cert, sk)));

  let listener = TcpListener::bind(&args.bind_address).expect("Failed to bind to address");
  let dhcp_pool = Arc::new(Dhcp::default());

  loop {
    let Ok((socket, addr)) = listener.accept() else {
      eprintln!("Connection failure");
      continue;
    };

    let dhcp_pool = Arc::clone(&dhcp_pool);
    std::thread::spawn(move || handle_client(socket, addr, context, dhcp_pool));
  }
}

fn handle_client(stream: TcpStream, addr: SocketAddr, context: &PqsContext, dhcp: Arc<Dhcp>) {
  println!("Connection from: {addr}");
  stream
    .set_read_timeout(Some(std::time::Duration::from_millis(1000)))
    .unwrap();
  let mut stream = match PqsChannel::new(stream, context) {
    Ok(res) => res,
    Err(err) => {
      eprintln!("Failed to establish connection: {err}");
      return;
    }
  };
  let (client_ip, receiver) = dhcp.new_client().unwrap();
  stream.write_all(&client_ip).unwrap();
  loop {
    match stream.read_sized() {
      Ok(res) => {
        if let Some(dst_ip) = parse_packet(&res) {
          println!("redirected packet: {:?}", dhcp.send(dst_ip, res));
        }
      }
      Err(err) => {
        if !matches!(
          err.kind(),
          std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ) {
          eprintln!("{err:?}");
          break;
        }
      }
    }
    match receiver.try_recv() {
      Ok(res) => {
        if stream.write_sized(res).is_err() {
          break;
        }
      }
      Err(mpsc::TryRecvError::Empty) => continue,
      _ => break,
    };
  }
  dhcp.free(client_ip).unwrap();
}

fn parse_packet(data: &[u8]) -> Option<[u8; 4]> {
  let packet = etherparse::SlicedPacket::from_ip(data).unwrap();
  let ip = packet.ip?;
  match ip {
    etherparse::InternetSlice::Ipv4(header, _exts) => {
      let header = header.to_header();
      println!("packet header: {header:?}");
      return Some(header.destination);
    }
    etherparse::InternetSlice::Ipv6(header, _exts) => {
      let header = header.to_header();
      println!("packet header: {header:?}");
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
  #[arg(short, long, default_value_t = ("server.cert".to_owned()))]
  certificate_file: String,
}
