use std::{sync::Arc, io::{Read, Write}};

use openssl::hash::MessageDigest;

use crate::context::PqDtlsContext;

pub struct SharedSecret {
  data: rmce::PlainSecret
}

pub fn server<S: Read + Write>(context: &Arc<PqDtlsContext>, stream: &mut S) -> std::io::Result<SharedSecret> {
  let mut buffer = [0u8; rmce::ShareableSecret::SIZE];
  stream.read_exact(&mut buffer[..32]);
  let mut hasher = openssl::hash::Hasher::new(MessageDigest::sha256()).unwrap();
  hasher.update(&buffer[..32]);
  let my_cert = context.get_cert().serialize();
  hasher.update(my_cert.as_slice());
  stream.write_all(my_cert.as_slice())?;
  stream.read_exact(&mut buffer)?;
  hasher.update(&buffer);
  let shared_secret = rmce::ShareableSecret::from(buffer);
  let secret = shared_secret.open(openssl::cipher::Cipher::aes_128_cbc().key_length(), &context.get_priv().data);

  Ok(SharedSecret { data: rmce::PlainSecret::from(secret) })
}