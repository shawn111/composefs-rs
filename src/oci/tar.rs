use std::{
    borrow::Cow,
    collections::HashMap,
    ffi::{
        OsStr,
        OsString,
    },
    os::unix::prelude::OsStrExt,
    path::{
        Path,
        PathBuf,
    },
    io::{
        Read,
        Write,
    },
};

use anyhow::{
    bail,
    Result
};
use composefs::dumpfile::{
    Entry,
    Item,
    Mtime,
    Xattr,
};
use rustix::fs::{
    FileType,
    makedev
};
use tar::{
    EntryType,
    Header,
    PaxExtensions,
};

use crate::{
    fsverity::Sha256HashValue,
    splitstream::{
        SplitStreamData,
        SplitStreamReader,
        SplitStreamWriter,
    },
    util::read_exactish,
};

fn read_header<R: Read>(reader: &mut R) -> Result<Option<Header>> {
    let mut header = Header::new_gnu();
    if read_exactish(reader, header.as_mut_bytes())? {
        Ok(Some(header))
    } else {
        Ok(None)
    }
 }

/// Splits the tar file from tar_stream into a Split Stream.  The store_data function is
/// responsible for ensuring that "external data" is in the composefs repository and returns the
/// fsverity hash value of that data.
pub fn split<R: Read, W: Write, F: FnMut(&[u8]) -> Result<Sha256HashValue>>(
    tar_stream: &mut R,
    split_stream: &mut W,
    mut store_data: F,
) -> Result<()> {
    let mut writer = SplitStreamWriter::new(split_stream);

    while let Some(header) = read_header(tar_stream)? {
        // the header always gets stored as inline data
        writer.write_inline(header.as_bytes());

        if header.as_bytes() == &[0u8; 512] {
            continue;
        }

        // read the corresponding data, if there is any
        let actual_size = header.entry_size()? as usize;
        let storage_size = (actual_size + 511) & !511;
        let mut buffer = vec![0u8; storage_size];
        tar_stream.read_exact(&mut buffer)?;

        if header.entry_type() == EntryType::Regular && storage_size > 0 {
            // non-empty regular file: store the data in the object store
            let padding = buffer.split_off(actual_size);
            let reference = store_data(&buffer)?;
            writer.write_reference(reference, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }

    // flush out any remaining inline data
    writer.done()
}

fn path_from_tar(long: &[u8], short: &[u8]) -> PathBuf {
    // Prepend leading /
    let mut path = vec![b'/'];
    path.extend(if !long.is_empty() { long } else { short });

    // Drop trailing '/' characters in case of directories.
    // https://github.com/rust-lang/rust/issues/122741
    // path.pop_if(|x| x == &b'/');
    if path.last() == Some(&b'/') {
        path.pop();
    }

    PathBuf::from(OsStr::from_bytes(&path))
}

fn symlink_target_from_tar(long: &[u8], short: &[u8]) -> PathBuf {
    // If I was smarter, I could do this without a copy....
    let mut path = vec![];
    path.extend(if !long.is_empty() { long } else { short });
    PathBuf::from(OsStr::from_bytes(&path))
}

pub fn ls<R: Read>(split_stream: &mut R) -> Result<()> {
    let mut reader = SplitStreamReader::new(split_stream);
    let mut gnu_longname: Vec<u8> = vec![];
    let mut gnu_longlink: Vec<u8> = vec![];
    let mut pax_headers = HashMap::new();

    // no root entry in the tar
    println!("{}", Entry {
        path: Cow::Borrowed(Path::new("/")),
        uid: 0,
        gid: 0,
        mode: FileType::Directory.as_raw_mode() | 0o755,
        mtime: Mtime { sec: 0, nsec: 0 },
        item: Item::Directory { size: 0, nlink: 1 },
        xattrs: vec![]
    });

    loop {
        let mut buf = [0u8; 512];
        if !reader.read_inline_exact(&mut buf)? {
            return Ok(());
        }

        if buf == [0u8; 512] {
            return Ok(());
        }

        let header = tar::Header::from_byte_slice(&buf);
        assert!(header.as_ustar().is_some());

        let nlink = 1;
        let size = header.entry_size()?;

        let item = match reader.read_exact(size as usize, (size + 511 & !511) as usize)? {
            SplitStreamData::External(id) => match header.entry_type() {
                EntryType::Regular | EntryType::Continuous => Item::Regular {
                    fsverity_digest: Some(hex::encode(id)),
                    inline_content: None,
                    nlink, size
                },
                _ => bail!("Unsupported external-chunked entry {:?} {}", header, hex::encode(id)),
            },
            SplitStreamData::Inline(content) => match header.entry_type() {
                EntryType::GNULongLink => {
                    gnu_longlink.extend(content);
                    continue;
                },
                EntryType::GNULongName => {
                    gnu_longname.extend(content);
                    continue;
                },
                EntryType::XGlobalHeader => {
                    todo!();
                },
                EntryType::XHeader => {
                    for item in PaxExtensions::new(&content) {
                        if let Ok(extension) = item {
                            pax_headers.insert(String::from(extension.key()?), Vec::from(extension.value_bytes()));
                        }
                    }
                    continue;
                },
                EntryType::Directory => Item::Directory { size, nlink },
                EntryType::Regular | EntryType::Continuous => Item::Regular {
                    fsverity_digest: None,
                    inline_content: Some(content.into()),
                    nlink, size
                },
                EntryType::Link => Item::Hardlink {
                    target: {
                        let Some(link_name) = header.link_name_bytes() else { bail!("link without a name?") };
                        Cow::Owned(path_from_tar(&gnu_longlink, &link_name))
                    }
                },
                EntryType::Symlink => Item::Symlink {
                    target: {
                        let Some(link_name) = header.link_name_bytes() else { bail!("symlink without a name?") };
                        Cow::Owned(symlink_target_from_tar(&gnu_longlink, &link_name))
                    },
                    nlink
                },
                EntryType::Block | EntryType::Char => Item::Device {
                    rdev: match (header.device_major()?, header.device_minor()?) {
                        (Some(major), Some(minor)) => makedev(major, minor),
                        _ => bail!("Device entry without device numbers?"),
                    },
                    nlink
                },
                EntryType::Fifo => Item::Fifo { nlink },
                _ => {
                    todo!("Unsupported entry {:?} {:?}", header, content);
                }
            }
        };

        let mut xattrs = vec![];
        for (key, value) in &pax_headers {
            if key == "path" {
                // TODO: why?!
            } else if key == "linkpath" {
                // TODO: why?!
            } else if let Some(xattr) = key.strip_prefix("SCHILY.xattr.") {
                xattrs.push(Xattr { key: Cow::Owned(OsString::from(xattr)), value: Cow::Borrowed(&value) });
            } else {
                todo!("pax header {key:?}");
            }
        }

        let entry = Entry {
            path: Cow::Owned(path_from_tar(&gnu_longname, &header.path_bytes())),
            uid: header.uid()? as u32,
            gid: header.gid()? as u32,
            mode: header.mode()? | match header.entry_type() {
                EntryType::Directory => FileType::Directory,
                EntryType::Regular => FileType::RegularFile,
                EntryType::Symlink => FileType::Symlink,
                EntryType::Char => FileType::CharacterDevice,
                EntryType::Block => FileType::BlockDevice,
                EntryType::Fifo => FileType::Fifo,
                _ => { continue; }
            }.as_raw_mode(),
            mtime: Mtime { sec: header.mtime()?, nsec: 0 },
            item,
            xattrs
        };

        println!("{}", entry);

        gnu_longlink.clear();
        gnu_longname.clear();
        pax_headers.clear();
    }
}
