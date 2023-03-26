use std::{
  collections::{BTreeMap, BinaryHeap},
  io::ErrorKind,
  sync::{mpsc, Mutex},
};

pub struct Dhcp {
  base: u32,
  next: Mutex<BinaryHeap<u8>>,
  clients: Mutex<BTreeMap<u32, mpsc::Sender<Vec<u8>>>>,
}

impl Default for Dhcp {
  fn default() -> Self {
    let mut next = BinaryHeap::new();
    next.extend(2..253);
    Self {
      base: (10 << 24) | (10 << 16) | (10 << 8) | (0 << 0),
      next: Mutex::new(next),
      clients: Default::default(),
    }
  }
}

impl Dhcp {
  pub fn new_client(&self) -> std::io::Result<([u8; 4], mpsc::Receiver<Vec<u8>>)> {
    let next_id = self.next.lock().unwrap().pop();
    let id = 255
      - next_id.ok_or(std::io::Error::new(
        ErrorKind::Other,
        "Too many devices on the network",
      ))?;
    let ip = self.base | id as u32;
    let ip_bytes = ip.to_be_bytes();
    let (tx, rx) = mpsc::channel();
    drop(self.clients.lock().unwrap().insert(ip, tx));
    println!("hand out ip: {:?}", ip_bytes);
    Ok((ip_bytes, rx))
  }
  pub fn free(&self, ip: [u8; 4]) -> std::io::Result<()> {
    println!("returned ip: {:?}", ip);
    let ip = u32::from_be_bytes(ip);
    if ip & 0xffffff00 != self.base {
      return Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Invalid ip address",
      ));
    }
    self
      .clients
      .lock()
      .unwrap()
      .remove(&ip)
      .ok_or(std::io::Error::new(
        ErrorKind::NotFound,
        "Device does not exist in pool",
      ))?;
    let id = (ip & 0xff) as u8;
    self.next.lock().unwrap().push(255 - id);
    Ok(())
  }
  pub fn send(&self, ip: [u8; 4], packet: Vec<u8>) -> std::io::Result<()> {
    let ip = u32::from_be_bytes(ip);
    if ip & 0xffffff00 != self.base {
      return Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Invalid ip address",
      ));
    }
    let clients = self.clients.lock().unwrap();
    let sender = clients.get(&ip).ok_or(std::io::Error::new(
      ErrorKind::NotFound,
      "Device does not exist in pool",
    ))?;
    sender
      .send(packet)
      .map_err(|err| std::io::Error::new(ErrorKind::ConnectionRefused, err))?;
    Ok(())
  }
}
