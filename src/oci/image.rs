use std::{
    ffi::{
        OsStr,
        OsString,
    },
    io::Read,
    path::Path,
};

use anyhow::{
    Result,
    bail,
};
use composefs::dumpfile::Item;

use crate::{
    oci,
    splitstream::SplitStreamReader,
};

pub struct DirEnt {
    name: OsString,
    inode: Inode,
}

pub struct Directory {
    entries: Vec<DirEnt>
}

pub enum Inode {
    Directory(Directory),
    File {
        content: Vec<u8>,
    }
}

pub fn recurse<'a>(dir: &'a mut Directory, name: &OsStr) -> Result<&'a mut Directory> {
    match dir.entries.last_mut() {
        // TODO: We assume that all items are added to the immediate-previous subdir.  That's
        // probably true for single layers but is going to stop being true when we start merging
        // multiple layers.
        Some(last_entry) if last_entry.name == name => match last_entry.inode {
            Inode::Directory(ref mut subdir) => Ok(subdir),
            _ => bail!("Parent directory is not a directory"),
        },
        _ => bail!("Unable to find parent directory"),
    }
}

pub fn add_entry(mut dir: &mut Directory, name: &Path, inode: Inode) -> Result<()> {
    if let Some(subdirs) = name.parent() {
        for segment in subdirs {
            if segment == "" || segment == "/" { // Path.parent() is really weird...
                continue;
            }
            dir = recurse(dir, segment)?;
        }
    }

    if let Some(filename) = name.file_name() {
        Ok(dir.entries.push(DirEnt { name: OsString::from(filename), inode }))
    } else {
        bail!("Invalid filename");
    }
}

pub fn merge<R: Read>(split_stream: &mut R) -> Result<()> {
    let mut root = Directory { entries: vec![] };

    let mut reader = SplitStreamReader::new(split_stream);
    while let Some(entry) = oci::tar::get_entry(&mut reader)? {
        let inode = match entry.item {
            Item::Directory { .. } => {
                Inode::Directory(Directory { entries: vec![] })
            },
            _ => {
                Inode::File { content: vec![] }
            }
        };

        add_entry(&mut root, &*entry.path, inode)?;
    }

    Ok(())
}

