pub mod image;
pub mod tar;

use std::io::Read;

use anyhow::Result;

use crate::{
    fsverity::Sha256HashValue,
    repository::Repository,
    oci::tar::get_entry,
};

pub fn import_layer(
    repo: &Repository, sha256: &Sha256HashValue, name: Option<&str>, tar_stream: &mut impl Read
) -> Result<Sha256HashValue> {
    Ok(repo.ensure_stream(sha256, |writer| tar::split(tar_stream, writer), name)?)
}

pub fn ls_layer(repo: &Repository, name: &str) -> Result<()> {
    let mut split_stream = repo.open_stream(name, None)?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{}", entry);
    }

    Ok(())
}
