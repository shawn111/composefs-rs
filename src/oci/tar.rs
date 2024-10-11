use std::{
    borrow::Cow,
    ffi::{
        OsStr,
        OsString,
    },
    os::unix::prelude::{
        OsStrExt,
        OsStringExt,
    },
    path::{
        Path,
        PathBuf,
    },
    io::Read,
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
pub fn split<R: Read>(
    tar_stream: &mut R,
    writer: &mut SplitStreamWriter,
) -> Result<()> {
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
            writer.write_external(&buffer, padding)?;
        } else {
            // else: store the data inline in the split stream
            writer.write_inline(&buffer);
        }
    }
    Ok(())
}

fn path_from_tar(pax: Option<Vec<u8>>, gnu: Vec<u8>, short: &[u8]) -> PathBuf {
    // Prepend leading /
    let mut path = vec![b'/'];
    if let Some(name) = pax {
        path.extend(name);
    } else if !gnu.is_empty() {
        path.extend(gnu);
    } else {
        path.extend(short);
    }

    // Drop trailing '/' characters in case of directories.
    // https://github.com/rust-lang/rust/issues/122741
    // path.pop_if(|x| x == &b'/');
    if path.last() == Some(&b'/') {
        path.pop(); // this is Vec<u8>, so that's a single char.
    }

    PathBuf::from(OsString::from_vec(path))
}

fn symlink_target_from_tar(pax: Option<Vec<u8>>, gnu: Vec<u8>, short: &[u8]) -> PathBuf {
    if let Some(name) = pax {
        PathBuf::from(OsString::from_vec(name))
    } else if !gnu.is_empty() {
        PathBuf::from(OsString::from_vec(gnu))
    } else {
        PathBuf::from(OsStr::from_bytes(short))
    }
}

pub fn get_entry<R: Read>(reader: &mut SplitStreamReader<R>) -> Result<Option<Entry<'static>>> {
    let mut gnu_longlink: Vec<u8> = vec![];
    let mut gnu_longname: Vec<u8> = vec![];
    let mut pax_longlink: Option<Vec<u8>> = None;
    let mut pax_longname: Option<Vec<u8>> = None;
    let mut xattrs = vec![];

    loop {
        let mut buf = [0u8; 512];
        if !reader.read_inline_exact(&mut buf)? || buf == [0u8; 512] {
            return Ok(None);
        }

        let header = tar::Header::from_byte_slice(&buf);
        assert!(header.as_ustar().is_some());

        let nlink = 1;
        let size = header.entry_size()?;

        let item = match reader.read_exact(size as usize, ((size + 511) & !511) as usize)? {
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
                        let extension = item?;
                        let key = extension.key()?;
                        let value = Vec::from(extension.value_bytes());

                        if key == "path" {
                            pax_longname = Some(value);
                        } else if key == "linkpath" {
                            pax_longlink = Some(value);
                        } else if let Some(xattr) = key.strip_prefix("SCHILY.xattr.") {
                            xattrs.push(Xattr {
                                key: Cow::Owned(OsString::from(xattr)),
                                value: Cow::Owned(value)
                            });
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
                        Cow::Owned(path_from_tar(pax_longlink, gnu_longlink, &link_name))
                    }
                },
                EntryType::Symlink => Item::Symlink {
                    target: {
                        let Some(link_name) = header.link_name_bytes() else { bail!("symlink without a name?") };
                        Cow::Owned(symlink_target_from_tar(pax_longlink, gnu_longlink, &link_name))
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

        let ifmt = match item {
            Item::Directory { .. } => FileType::Directory,
            Item::Regular { .. } => FileType::RegularFile,
            Item::Device { .. } => if header.entry_type() == EntryType::Block {
                FileType::BlockDevice
            } else {
                FileType::CharacterDevice
            },
            Item::Fifo { .. } => FileType::Fifo,
            Item::Symlink { .. } => FileType::Symlink,
            Item::Hardlink { .. } => {
                // NB: For hardlinks we don't know the real type, but it's also not important:
                // mkcomposefs will ignore it.  We need to fill something in, though.
                FileType::RegularFile
            },
        }.as_raw_mode();

        return Ok(Some(Entry {
            path: Cow::Owned(path_from_tar(pax_longname, gnu_longname, &header.path_bytes())),
            uid: header.uid()? as u32,
            gid: header.gid()? as u32,
            mode: header.mode()? | ifmt,
            mtime: Mtime { sec: header.mtime()?, nsec: 0 },
            item,
            xattrs
        }));
    }
}

pub fn ls<R: Read>(split_stream: &mut R) -> Result<()> {
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

    let mut reader = SplitStreamReader::new(split_stream);
    while let Some(entry) = get_entry(&mut reader)? {
        println!("{}", entry);
    }
    Ok(())
}
