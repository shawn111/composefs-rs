use std::{
    collections::HashMap,
    ffi::{
        OsStr,
        OsString,
    },
    io::Write,
    os::unix::ffi::OsStrExt,
    path::{
        PathBuf,
        Path,
    },
    rc::Rc,
};

use anyhow::Result;
use rustix::fs::FileType;

use crate::image::{
    DirEnt,
    Directory,
    FileSystem,
    Inode,
    Leaf,
    LeafContent,
    Stat,
};

struct DumpfileWriter<'a, W: Write> {
    hardlinks: HashMap<*const Leaf, PathBuf>,
    writer: &'a mut W
}

impl<'a, W: Write> DumpfileWriter<'a, W> {
    fn new(writer: &'a mut W) -> Self {
        Self { hardlinks: HashMap::new(), writer }
    }

    fn write_escaped(&mut self, string: &OsStr) -> Result<()> {
        for c in string.as_bytes() {
            let c = *c;

            if c < b'!' || c == b'=' || c == b'\\' || c > b'~' {
                write!(self.writer, "\\x{:02x}", c)?;
            } else {
                write!(self.writer, "{}", c as char)?;
            }
        }

        Ok(())
    }

    fn write_stat(&mut self, stat: &Stat, size: u64, nlink: usize, ifmt: FileType, rdev: u64) -> Result<()> {
        let mode = stat.st_mode | ifmt.as_raw_mode();
        Ok(write!(self.writer, " {size} {mode:o} {nlink} {} {} {} {}.0", stat.st_uid, stat.st_gid, rdev, stat.st_mtim_sec)?)
    }

    fn write_xattrs(&mut self, _xattrs: &[(OsString, Vec<u8>)]) -> Result<()> {
        Ok(())
    }

    fn write_dir(&mut self, path: &Path, dir: &Directory) -> Result<()> {
        self.write_escaped(path.as_os_str())?;
        let nlink = dir.entries.len();
        self.write_stat(&dir.stat, 0, nlink, FileType::Directory, 0)?;
        write!(self.writer, " - - - ")?;
        self.write_xattrs(&dir.stat.xattrs)?;
        writeln!(self.writer, "")?;

        for DirEnt { name, inode } in dir.entries.iter() {
            let subpath = path.join(name);

            match inode {
                Inode::Directory(ref dir) => {
                    self.write_dir(&subpath, dir)?;
                },
                Inode::Leaf(ref leaf) => {
                    self.write_leaf(&subpath, leaf)?;
                }
            }
        }
        Ok(())
    }

    fn write_leaf(&mut self, path: &Path, leaf: &Rc<Leaf>) -> Result<()> {
        self.write_escaped(path.as_os_str())?;
        let nlink = Rc::strong_count(leaf);

        if nlink > 1 {
            // This is a hardlink.  We need to handle that specially.
            let ptr = Rc::as_ptr(leaf);
            if let Some(target) = self.hardlinks.get(&ptr) {
                write!(self.writer, " - @0 - - - - - ")?;
                self.write_escaped(&OsString::from(target.as_os_str()))?; // TODO: ugh
                writeln!(self.writer, " - -")?;
                return Ok(());
            }
            self.hardlinks.insert(ptr, PathBuf::from(path)); // TODO: ugh
        }

        match leaf.content {
            LeafContent::InlineFile(ref data) => {
                self.write_stat(&leaf.stat, data.len() as u64, nlink, FileType::RegularFile, 0)?;
                write!(self.writer, " - ")?;
                self.write_escaped(OsStr::from_bytes(data))?;
                write!(self.writer, " -")?;
            },
            LeafContent::ExternalFile(ref id, size) => {
                self.write_stat(&leaf.stat, size, nlink, FileType::RegularFile, 0)?;
                write!(self.writer, " {:02x}/{} - {}", id[0], hex::encode(&id[1..]), hex::encode(id))?;
            },
            LeafContent::BlockDevice(rdev) => {
                self.write_stat(&leaf.stat, 0, nlink, FileType::BlockDevice, rdev)?;
                write!(self.writer, " - - -")?;
            },
            LeafContent::CharacterDevice(rdev) => {
                self.write_stat(&leaf.stat, 0, nlink, FileType::CharacterDevice, rdev)?;
                write!(self.writer, " - - -")?;
            },
            LeafContent::Fifo => {
                self.write_stat(&leaf.stat, 0, nlink, FileType::Fifo, 0)?;
                write!(self.writer, " - - -")?;
            },
            LeafContent::Socket => {
                self.write_stat(&leaf.stat, 0, nlink, FileType::Socket, 0)?;
                write!(self.writer, " - - -")?;
            },
            LeafContent::Symlink(ref target) => {
                self.write_stat(&leaf.stat, 0, nlink, FileType::Symlink, 0)?;
                write!(self.writer, " ")?;
                self.write_escaped(target.as_os_str())?;
                write!(self.writer, " - -")?;
            },
        }

        self.write_xattrs(&leaf.stat.xattrs)?;
        writeln!(self.writer, "")?;

        Ok(())
    }
}

pub fn write_dumpfile<W: Write>(writer: &mut W, fs: &FileSystem) -> Result<()> {
    Ok(DumpfileWriter::new(writer).write_dir(Path::new("/"), &fs.root)?)
}
