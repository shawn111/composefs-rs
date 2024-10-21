use std::{
    io::Read,
    os::fd::{
        AsFd,
        AsRawFd,
    },
};

use anyhow::{
    Context,
    Result,
};

use crate::fsverity::{
    FsVerityHashValue,
    Sha256HashValue,
};

pub fn proc_self_fd<A: AsFd>(fd: &A) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}

// we can't use Read::read_exact() because we need to be able to detect EOF
pub fn read_exactish<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool> {
    let buflen = buf.len();
    let mut todo: &mut [u8] = buf;

    while !todo.is_empty() {
        match reader.read(todo) {
            Ok(0) => match todo.len() {
                s if s == buflen => return Ok(false),  // clean EOF
                _ => Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?
            },
            Ok(n) => {
                todo = &mut todo[n..];
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                continue;
            }
            Err(e) => {
                Err(e)?;
            }
        }
    }

    Ok(true)
}

pub fn parse_sha256(string: impl AsRef<str>) -> Result<Sha256HashValue> {
    let mut value = Sha256HashValue::EMPTY;
    hex::decode_to_slice(string.as_ref(), &mut value)
        .context("Invalid SHA256 hash value")?;
    Ok(value)
}
