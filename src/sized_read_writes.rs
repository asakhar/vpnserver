use std::io::{Read, Result, Write};

pub trait ReadSizedExt {
  fn read_sized(&mut self) -> Result<Vec<u8>>;
}

impl<T: Read> ReadSizedExt for T {
  fn read_sized(&mut self) -> Result<Vec<u8>> {
    let mut size_buf = [0u8; std::mem::size_of::<usize>()];
    self.read_exact(&mut size_buf)?;
    let size = usize::from_be_bytes(size_buf);
    let mut result = vec![0u8; size];
    self.read_exact(&mut result)?;
    Ok(result)
  }
}
pub trait WriteSizedExt {
  fn write_sized(&mut self, data: impl AsRef<[u8]>) -> Result<()>;
}

impl<T: Write> WriteSizedExt for T {
  fn write_sized(&mut self, data: impl AsRef<[u8]>) -> Result<()> {
    let data = data.as_ref();
    self.write_all(&data.len().to_be_bytes())?;
    self.write_all(data)?;
    Ok(())
  }
}
