use std::{
    ffi::OsStr,
    os::unix::ffi::OsStrExt,
};

use anyhow::{
    Result,
    bail,
};
use crate::{
    dumpfile::write_dumpfile,
    image::{
        FileSystem,
        Leaf,
    },
    oci,
    repository::Repository,
    splitstream::SplitStreamReader,
};

fn is_whiteout(name: &OsStr) -> Option<&OsStr> {
    let bytes = name.as_bytes();
    if bytes.len() > 4 && &bytes[0..4] == b".wh." {
        Some(OsStr::from_bytes(&bytes[4..]))
    } else {
        None
    }
}

pub fn process_entry(filesystem: &mut FileSystem, entry: oci::tar::TarEntry) -> Result<()> {
    if let Some(filename) = entry.path.file_name() {
        if let Some(whiteout) = is_whiteout(filename) {
            filesystem.remove(&entry.path.parent().unwrap().join(whiteout))?;
        } else {
            match entry.item {
                oci::tar::TarItem::Directory => {
                    filesystem.mkdir(&entry.path, entry.stat)?;
                },
                oci::tar::TarItem::Leaf(content) => {
                    filesystem.insert(&entry.path, Leaf { stat: entry.stat, content })?;
                },
                oci::tar::TarItem::Hardlink(target) => {
                    filesystem.hardlink(&entry.path, &target)?;
                },
            }
        }
    } else {
        bail!("Invalid filename");
    }
    Ok(())
}

pub fn create_image(repo: &Repository, layers: &Vec<String>) -> Result<()> {
    let mut filesystem = FileSystem::new();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer)?;
        let mut reader = SplitStreamReader::new(&mut split_stream);
        while let Some(entry) = oci::tar::get_entry(&mut reader)? {
           process_entry(&mut filesystem, entry)?;
        }
    }

    let mut stdout = std::io::stdout();
    write_dumpfile(&mut stdout, &filesystem)?;

    Ok(())
}
