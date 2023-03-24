use std::{
  io::{Read, Write},
  path::PathBuf,
  sync::Arc,
};

use crate::{handshake::SharedSecret, sized_read_writes::{ReadSizedExt, WriteSizedExt}};

pub struct Signature(Box<[u8; dilithium::params::BYTES]>);

pub struct Certificate {
  pub pub_key: rmce::PublicKey,
  pub issuer: String,
  pub owner: String,
  pub signature: Signature,
}

impl Certificate {
  pub fn from_file<P: AsRef<std::path::Path>>(p: P) -> std::io::Result<Self> {
    let mut file = std::fs::File::open(p.as_ref())?;
    Self::deserialize(file)
  }
  pub fn deserialize<Data: Read>(mut data: Data) -> std::io::Result<Self> {
    let mut pub_key_buf = vec![0u8; rmce::PublicKey::SIZE];
    data.read_exact(&mut pub_key_buf)?;
    let pub_key = rmce::PublicKey::try_from(pub_key_buf.as_slice()).unwrap();
    let issuer = String::from_utf8(data.read_sized()?)
      .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    let owner = String::from_utf8(data.read_sized()?)
      .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    let mut sig_buf = vec![0u8; dilithium::params::BYTES];
    data.read_exact(&mut sig_buf)?;
    let signature = Signature(sig_buf.into_boxed_slice().try_into().unwrap());
    Ok(Self {
      pub_key,
      issuer,
      owner,
      signature,
    })
  }
  pub fn serialize(&self) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(self.pub_key.as_bytes());
    buffer.write_sized(self.issuer.as_bytes()).unwrap();
    buffer.write_sized(self.owner.as_bytes()).unwrap();
    buffer.extend_from_slice(self.signature.0.as_ref());
    buffer
  }
}

pub struct PrivateKey {
  pub data: rmce::SecretKey,
}

pub struct PqDtlsContext {
  cert: Option<Certificate>,
  pkey: Option<PrivateKey>,
}

impl PqDtlsContext {
  pub fn get_cert<'a>(self: &'a Arc<Self>) -> &'a Certificate {
    self.cert.as_ref().unwrap()
  }
  pub fn get_priv<'a>(self: &'a Arc<Self>) -> &'a PrivateKey {
    self.pkey.as_ref().unwrap()
  }
}

#[derive(Debug, Clone, Copy)]
pub enum Role {
  Server,
  Client,
}

impl PqDtlsContext {
  pub fn session<S: Read + Write>(self: &Arc<Self>, stream: &mut S, role: Role) -> PqDtlsSession {
    let secret = match role {
      Role::Server => crate::handshake::server(self, stream).unwrap(),
      Role::Client => todo!(), //handshake::client(self, stream),
    };
    PqDtlsSession {
      context: Arc::clone(self),
      secret,
    }
  }
}

pub struct PqDtlsSession {
  context: Arc<PqDtlsContext>,
  secret: SharedSecret,
}

struct PqDtlsStream<S: Read + Write> {
  stream: S,
  session: PqDtlsSession,
}

struct PqDtlsAcceptor {
  context: Arc<PqDtlsContext>,
}

impl PqDtlsAcceptor {
  pub fn accept<S: Read + Write>(&self, mut stream: S) -> PqDtlsStream<S> {
    let session = self.context.session(&mut stream, Role::Server);
    PqDtlsStream { stream, session }
  }
}

struct PqDtlsConnector {
  context: Arc<PqDtlsContext>,
}

struct BuilderInternal {
  private_key_file: Option<PathBuf>,
  certificate_file: Option<PathBuf>,
}

struct PqDtlsAcceptorBuilder {
  internal: BuilderInternal,
}

struct PqDtlsConnectorBuilder {
  internal: BuilderInternal,
}
