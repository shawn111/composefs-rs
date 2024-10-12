use std::{
    ffi::{
        OsStr,
        OsString,
    },
    io::Write,
    os::unix::ffi::OsStrExt,
    path::Path,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use composefs::dumpfile::Item;

use crate::{
    oci,
    repository::Repository,
    splitstream::SplitStreamReader,
};

pub struct DirEnt {
    name: OsString,
    inode: Inode,
}

pub struct Directory {
    entries: Vec<DirEnt>
}

impl Directory {
    pub fn find_entry(&self, name: &OsStr) -> Result<usize, usize> {
        // performance TODO: on the first pass through we'll almost always want the last entry
        // (since the layer is sorted and we're always inserting into the directory that we just
        // created) maybe add a special case for that?
        self.entries.binary_search_by_key(&name, |e| &e.name)
    }

    pub fn recurse<'a>(&'a mut self, name: &OsStr) -> Result<&'a mut Directory> {
        match self.find_entry(name) {
            Ok(idx) => match self.entries[idx].inode {
                Inode::Directory(ref mut subdir) => Ok(subdir),
                _ => bail!("Parent directory is not a directory"),
            },
            _ => bail!("Unable to find parent directory {:?}", name),
        }
    }

    pub fn insert(&mut self, name: &OsStr, inode: Inode) {
        match self.find_entry(name) {
            Ok(idx) => {
                // found existing item.
                if let Inode::Directory { .. } = inode {
                    // don't replace directories!
                } else {
                    self.entries[idx].inode = inode;
                }
            }
            Err(idx) => {
                self.entries.insert(idx, DirEnt { name: OsString::from(name), inode });
            }
        }
    }

    pub fn delete(&mut self, name: &OsStr) {
        match self.find_entry(name) {
            Ok(idx) => { self.entries.remove(idx); }
            _ => { /* not an error to remove an already-missing file*/ }
        }
    }

    pub fn write<W: Write>(&self, writer: &mut W, dirname: &Path) -> Result<()> {
        writeln!(writer, "{:?} -> dir", dirname)?;
        for DirEnt { name, inode } in self.entries.iter() {
            let path = dirname.join(name);

            match inode {
                Inode::Directory(dir) => dir.write(writer, &path)?,
                Inode::File { .. } => writeln!(writer, "{:?} -> file", path)?,
            }
        }
        Ok(())
    }
}

pub enum Inode {
    Directory(Directory),
    File {
        content: Vec<u8>,
    }
}

fn is_whiteout(name: &OsStr) -> Option<&OsStr> {
    let bytes = name.as_bytes();
    if bytes.len() > 4 && &bytes[0..4] == b".wh." {
        Some(OsStr::from_bytes(&bytes[4..]))
    } else {
        None
    }
}

pub fn process_entry(mut dir: &mut Directory, name: &Path, inode: Inode) -> Result<()> {
    if let Some(subdirs) = name.parent() {
        for segment in subdirs {
            if segment.is_empty() || segment == "/" { // Path.parent() is really weird...
                continue;
            }
            dir = dir.recurse(segment)
                .with_context(|| format!("Trying to insert item {:?}", name))?;
        }
    }

    if let Some(filename) = name.file_name() {
        if let Some(whiteout) = is_whiteout(filename) {
            dir.delete(whiteout);
        } else {
            dir.insert(filename, inode);
        }
    } else {
        bail!("Invalid filename");
    }
    Ok(())
}

pub fn create_image(repo: &Repository, layers: &Vec<String>) -> Result<()> {
    let mut root = Directory { entries: vec![] };

    for layer in layers {
        let mut split_stream = repo.open_stream(layer)?;
        let mut reader = SplitStreamReader::new(&mut split_stream);
        while let Some(entry) = oci::tar::get_entry(&mut reader)? {
            let inode = match entry.item {
                Item::Directory { .. } => {
                    Inode::Directory(Directory { entries: vec![] })
                },
                _ => {
                    Inode::File { content: vec![] }
                }
            };

            process_entry(&mut root, &entry.path, inode)?;
        }
    }

    root.write(&mut std::io::stdout(), Path::new("/"))?;

    Ok(())
}
