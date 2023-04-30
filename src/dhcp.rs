use std::{
  collections::BinaryHeap,
  io::ErrorKind,
  net::Ipv4Addr,
  time::Duration,
};

use log::debug;

use transient_hashmap::TransientHashMap;

pub trait ClientRequest<Client> {
  fn into_client(ip: Ipv4Addr) -> Client;
}

pub struct Dhcp<Client> {
  net_addr: u32,
  net_mask: u32,
  vacant: BinaryHeap<std::cmp::Reverse<u32>>,
  clients: TransientHashMap<u32, Client>,
}

impl<Client> Dhcp<Client> {
  pub fn new(net_addr: Ipv4Addr, net_mask_suffix: u8, client_data_lifetime: Duration) -> Self {
    assert!(net_mask_suffix < 31, "Invalid network mask");
    let net_addr = u32::from_be_bytes(net_addr.octets());
    let unit_mask = (1 << net_mask_suffix) - 1;
    let net_mask = !unit_mask;
    assert_eq!(
      net_addr & unit_mask,
      0,
      "Invalid network address {net_addr}/{net_mask_suffix}"
    );
    let lifetime_sec = client_data_lifetime.as_secs();
    assert!(lifetime_sec <= u32::MAX as u64, "Too long lifetime");
    let mut vacant = Default::default();
    let last = net_addr | (unit_mask - 2);
    let first = net_addr | 2;
    let ips = std::cmp::Reverse(last)..=std::cmp::Reverse(first);
    vacant.extend(ips);
    Self {
      net_addr,
      net_mask,
      vacant,
      clients: TransientHashMap::new(client_data_lifetime.as_secs().into()),
    }
  }
}

impl<Client> Default for Dhcp<Client> {
  fn default() -> Self {
    Self::new(Ipv4Addr::new(10, 10, 10, 0), 24, Duration::from_secs(60))
  }
}

impl<Client> Dhcp<Client> {
  pub fn new_client(&mut self, request: impl ClientRequest<Client>) -> std::io::Result<Ipv4Addr> {
    let next_ip = self
      .vacant
      .pop()
      .ok_or(std::io::Error::new(
        ErrorKind::Other,
        "Too many devices on the network",
      ))?
      .0;
    let ip = Ipv4Addr::from(next_ip.to_be_bytes());
    self.clients.insert(ip, request.into_client(ip));
    debug!("hand out ip: {:?}", ip);
    Ok(ip)
  }
  pub fn prune(&mut self) {
    self.vacant.extend(self.clients.prune())
  }
  pub fn free(&mut self, ip: Ipv4Addr) -> std::io::Result<()> {
    debug!("returned ip: {:?}", ip);
    let ip = u32::from_be_bytes(ip.octets());
    if ip & self.net_mask != self.net_addr {
      return Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Ip address does not belong to this pool",
      ));
    }
    self.clients.remove(&ip).ok_or(std::io::Error::new(
      ErrorKind::NotFound,
      "Device does not exist in pool",
    ))?;
    self.vacant.push(std::cmp::Reverse(ip));
    Ok(())
  }
  pub fn get(&self, ip: Ipv4Addr) -> std::io::Result<&Client> {
    let ip = u32::from_be_bytes(ip.octets());
    if ip & self.net_mask != self.net_addr {
      return Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Ip address does not belong to this pool",
      ));
    }
    Ok(
      self
        .clients
        .get(&ip)
        .ok_or(std::io::Error::new(ErrorKind::NotFound, "Client not found"))?,
    )
  }
  pub fn get_mut(&mut self, ip: Ipv4Addr) -> std::io::Result<&mut Client> {
    let ip = u32::from_be_bytes(ip.octets());
    if ip & self.net_mask != self.net_addr {
      return Err(std::io::Error::new(
        ErrorKind::InvalidInput,
        "Ip address does not belong to this pool",
      ));
    }
    Ok(
      self
        .clients
        .get_mut(&ip)
        .ok_or(std::io::Error::new(ErrorKind::NotFound, "Client not found"))?,
    )
  }
}
