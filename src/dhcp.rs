use std::{
  collections::{BinaryHeap, HashMap},
  io::ErrorKind,
  net::Ipv4Addr,
};

use log::debug;

pub struct Dhcp {
  net_mask_suffix: u8,
  net_addr: Ipv4Addr,
  vacant: BinaryHeap<std::cmp::Reverse<u32>>,
  clients: HashMap<u32, uuid::Uuid>,
}

impl Dhcp {
  pub fn new(net_addr: Ipv4Addr, net_mask_suffix: u8) -> Self {
    assert!(net_mask_suffix < 31, "Invalid network mask");
    let net_addr_int = u32::from_be_bytes(net_addr.octets());
    let unit_mask = (1 << (32 - net_mask_suffix)) - 1;
    assert_eq!(
      net_addr_int & unit_mask,
      0,
      "Invalid network address {net_addr_int:032b}/{net_mask_suffix} ({:?}/{net_mask_suffix})",
      net_addr.octets()
    );
    let mut vacant: BinaryHeap<_> = Default::default();
    let last = net_addr_int | (unit_mask - 2);
    let first = net_addr_int | 2;
    let ips = first..=last;
    vacant.extend(ips.map(std::cmp::Reverse));
    Self {
      vacant,
      net_addr,
      net_mask_suffix,
      clients: HashMap::new(),
    }
  }
  pub fn get_net_mask_suffix(&self) -> u8 {
    self.net_mask_suffix
  }
}

impl Default for Dhcp {
  fn default() -> Self {
    Self::new(Ipv4Addr::new(10, 10, 10, 0), 24)
  }
}

impl Dhcp {
  pub fn get_self(&self) -> Ipv4Addr {
    let ip = u32::from_be_bytes(self.net_addr.octets()) | 0x00000001;
    Ipv4Addr::from(ip.to_be_bytes())
  }
  pub fn new_client(&mut self, id: uuid::Uuid) -> std::io::Result<Ipv4Addr> {
    let next_ip = self
      .vacant
      .pop()
      .ok_or(std::io::Error::new(
        ErrorKind::Other,
        "Too many devices on the network",
      ))?
      .0;
    let ip = Ipv4Addr::from(next_ip.to_be_bytes());
    self.clients.insert(next_ip, id);
    debug!("hand out ip: {:?}", ip);
    Ok(ip)
  }
  pub fn free(&mut self, ip: Ipv4Addr) -> std::io::Result<()> {
    debug!("returned ip: {:?}", ip);
    let ip = u32::from_be_bytes(ip.octets());
    self.clients.remove(&ip).ok_or(std::io::Error::new(
      ErrorKind::NotFound,
      "Device does not exist in pool",
    ))?;
    self.vacant.push(std::cmp::Reverse(ip));
    Ok(())
  }
  pub fn get(&self, ip_addr: Ipv4Addr) -> std::io::Result<uuid::Uuid> {
    let ip = u32::from_be_bytes(ip_addr.octets());
    Ok(
      self
        .clients
        .get(&ip)
        .copied()
        .ok_or(std::io::Error::new(ErrorKind::NotFound, format!("Client not found: {ip_addr}")))?,
    )
  }
  pub fn is_broadcast(&self, ip: Ipv4Addr) -> bool {
    let ip = u32::from_be_bytes(ip.octets());
    let unit_mask = (1 << (32 - self.net_mask_suffix)) - 1;
    (ip & unit_mask).count_ones() == unit_mask.count_ones()
  }
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;

  use uuid::Uuid;

  use super::Dhcp;

  #[test]
  fn default_gives_right_addresses() {
    let mut dhcp = Dhcp::default();

    let ids: Vec<_> = (2..254).map(|i| (i, Uuid::new_v4())).collect();
    for (i, id) in ids.iter() {
      assert_eq!(dhcp.new_client(*id).unwrap(), Ipv4Addr::new(10, 10, 10, *i));
    }
    for (i, id) in ids {
      assert_eq!(dhcp.get(Ipv4Addr::new(10, 10, 10, i)).unwrap(), id)
    }
    dhcp.new_client(Uuid::new_v4()).unwrap_err();
  }
  #[test]
  fn test_new() {
    let mut dhcp = Dhcp::new(Ipv4Addr::new(192, 168, 128, 0), 17);
    let ids: Vec<_> = (2u32..0b111111111111110)
      .map(|i| (i, Uuid::new_v4()))
      .collect();
    for (i, id) in ids {
      let low = i % 256;
      let high = i / 256;
      assert_eq!(
        dhcp.new_client(id).unwrap(),
        Ipv4Addr::new(192, 168, 128 | high as u8, low as u8)
      );
    }
    dhcp.new_client(Uuid::new_v4()).unwrap_err();
  }
  #[test]
  fn test_free() {
    let mut dhcp = Dhcp::default();

    let ids: Vec<_> = (2..20).map(|i| (i, Uuid::new_v4())).collect();
    for (i, id) in ids.iter() {
      assert_eq!(dhcp.new_client(*id).unwrap(), Ipv4Addr::new(10, 10, 10, *i));
    }
    dhcp.free(Ipv4Addr::new(10, 10, 10, 2)).unwrap();
    assert_eq!(
      dhcp.new_client(ids.first().unwrap().1).unwrap(),
      Ipv4Addr::new(10, 10, 10, 2)
    );
  }
}
