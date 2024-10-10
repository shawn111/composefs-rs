pub mod tar;

use std::io::Read;

use anyhow::Result;

use crate::{
    fsverity::Sha256HashValue,
    repository::Repository
};

pub fn import_layer<R: Read>(repo: &Repository, name: &str, tar_stream: &mut R) -> Result<()> {
    let mut split_stream = zstd::stream::write::Encoder::new(vec![], 0)?;

    tar::split(
        tar_stream,
        &mut split_stream,
        |data: &[u8]| -> Result<Sha256HashValue> {
            repo.ensure_object(data)
        }
    )?;

    let object_id = repo.ensure_object(&split_stream.finish()?)?;
    repo.link_ref(name, "streams", object_id)
}

pub fn ls_layer(repo: &Repository, name: &str) -> Result<()> {
    tar::ls(&mut repo.open_stream(name)?)
}
