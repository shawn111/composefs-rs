use std::{
    collections::HashSet,
    ffi::CStr,
    fs::File,
    io::{
        ErrorKind,
        Read,
        Write,
    },
    os::fd::OwnedFd,
    path::{
        Path,
        PathBuf,
    },
    process::Command,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use rustix::fs::{
    FileType,
    Dir,
    Access,
    AtFlags,
    CWD,
    FlockOperation,
    Mode,
    OFlags,
    accessat,
    fdatasync,
    flock,
    linkat,
    mkdirat,
    open,
    openat,
    readlinkat,
    symlinkat,
};

use crate::{
    fsverity::{
        FsVerityHashValue,
        Sha256HashValue,
        digest::FsVerityHasher,
        ioctl::{
            fs_ioc_enable_verity,
            fs_ioc_measure_verity,
        },
    },
    mount::mount_fd,
    splitstream::{
        splitstream_merge,
        splitstream_objects,
    },
    tar,
    util::proc_self_fd,
};

pub struct Repository {
    repository: OwnedFd,
    path: String,
}

impl Drop for Repository {
    fn drop(&mut self) {
        flock(&self.repository, FlockOperation::Unlock)
            .expect("repository unlock failed");
    }
}

impl Repository {
    pub fn open_path(path: String) -> Result<Repository> {
        // O_PATH isn't enough because flock()
        let repository = open(&path, OFlags::RDONLY, Mode::empty())
            .with_context(|| format!("Cannot open composefs repository '{path}'"))?;

        flock(&repository, FlockOperation::LockShared).
            with_context(|| format!("Cannot lock repository '{path}'"))?;

        Ok(Repository { repository, path })
    }

    pub fn open_user() -> Result<Repository> {
        let home = std::env::var("HOME")
            .with_context(|| "$HOME must be set when in user mode")?;

        Repository::open_path(format!("{}/.var/lib/composefs", home))
    }

    pub fn open_system() -> Result<Repository> {
        Repository::open_path("/sysroot/composefs".to_string())
    }

    fn ensure_parent<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        match path.as_ref().parent() {
            None => Ok(()),
            Some(path) if path == Path::new("") => Ok(()),
            Some(parent) => self.ensure_dir(parent)
        }
    }

    fn ensure_dir<P: AsRef<Path>>(&self, dir: P) -> Result<()> {
        self.ensure_parent(&dir)?;

        match mkdirat(&self.repository, dir.as_ref(), 0o777.into()) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err.into())
        }
    }

    pub fn ensure_object(&self, data: &[u8]) -> Result<Sha256HashValue> {
        let digest = FsVerityHasher::hash(data);
        let dir = PathBuf::from(format!("objects/{:02x}", digest[0]));
        let file = dir.join(hex::encode(&digest[1..]));

        if accessat(&self.repository, &file, Access::READ_OK, AtFlags::empty()) == Ok(()) {
            return Ok(digest);
        }

        self.ensure_dir(&dir)?;

        let fd = openat(&self.repository, &dir, OFlags::RDWR | OFlags::CLOEXEC | OFlags::TMPFILE, 0o666.into())?;
        rustix::io::write(&fd, data)?;  // TODO: no write_all() here...
        fdatasync(&fd)?;

        // We can't enable verity with an open writable fd, so re-open and close the old one.
        let ro_fd = open(proc_self_fd(&fd), OFlags::RDONLY, Mode::empty())?;
        drop(fd);

        fs_ioc_enable_verity::<&OwnedFd, Sha256HashValue>(&ro_fd)?;

        // double-check
        let measured_digest: Sha256HashValue = fs_ioc_measure_verity(&ro_fd)?;
        assert!(measured_digest == digest);

        if let Err(err) = linkat(CWD, proc_self_fd(&ro_fd), &self.repository, file, AtFlags::SYMLINK_FOLLOW) {
            if err.kind() != ErrorKind::AlreadyExists {
                return Err(err.into());
            }
        }

        drop(ro_fd);
        Ok(digest)
    }

    pub fn open_with_verity(&self, filename: &str, expected_verity: Sha256HashValue) -> Result<OwnedFd> {
        let fd = openat(&self.repository, filename, OFlags::RDONLY, Mode::empty())?;
        let measured_verity: Sha256HashValue = fs_ioc_measure_verity(&fd)?;
        if measured_verity != expected_verity {
            bail!("bad verity!")
        } else {
            Ok(fd)
        }
    }

    /// category is like "streams" or "images"
    /// name is like "refs/1000/user/xyz" (with '/') or a sha256 hex hash value (without '/')
    fn open_in_category(&self, category: &str, name: &str) -> Result<OwnedFd> {
        let filename = format!("{}/{}", category, name);

        if name.contains("/") {
            // no fsverity checking on this path
            Ok(openat(&self.repository, filename, OFlags::RDONLY, Mode::empty())?)
        } else {
            // this must surely be a hash value, and we want to verify it
            let mut hash = Sha256HashValue::EMPTY;
            hex::decode_to_slice(name, &mut hash)?;
            self.open_with_verity(&filename, hash)
        }
    }

    fn open_object(&self, id: Sha256HashValue) -> Result<OwnedFd> {
        self.open_with_verity(&format!("objects/{:02x}/{}", id[0], hex::encode(&id[1..])), id)
    }

    pub fn merge_splitstream<W: Write>(&self, name: &str, stream: &mut W) -> Result<()> {
        let file = File::from(self.open_in_category("streams", name)?);
        let mut split_stream = zstd::stream::read::Decoder::new(file)?;
        splitstream_merge(
            &mut split_stream,
            stream,
            |id: Sha256HashValue| -> Result<Vec<u8>> {
                let mut data = vec![];
                File::from(self.open_object(id)?).read_to_end(&mut data)?;
                Ok(data)
            }
        )?;

        Ok(())
    }

    pub fn import_tar<R: Read>(&self, name: &str, tar_stream: &mut R) -> Result<()> {
        let mut split_stream = zstd::stream::write::Encoder::new(vec![], 0)?;

        tar::split(
            tar_stream,
            &mut split_stream,
            |data: &[u8]| -> Result<Sha256HashValue> {
                self.ensure_object(data)
            }
        )?;

        let object_id = self.ensure_object(&split_stream.finish()?)?;
        self.link_ref(name, "streams", object_id)
    }

    /// this function is not safe for untrusted users
    pub fn import_image<R: Read>(&self, name: &str, image: &mut R) -> Result<()> {
        let mut data = vec![];
        image.read_to_end(&mut data)?;
        let object_id = self.ensure_object(&data)?;
        self.link_ref(name, "images", object_id)
    }

    pub fn ls(self, name: &str) -> Result<()> {
        let file = File::from(self.open_in_category("streams", name)?);
        let mut split_stream = zstd::stream::read::Decoder::new(file)?;
        crate::tar::ls(&mut split_stream)
    }

    pub fn mount(self, name: &str, mountpoint: &str) -> Result<()> {
        let image = self.open_in_category("images", name)?;
        let object_path = format!("{}/objects", self.path);
        mount_fd(image, &object_path, mountpoint)
    }

    fn link_ref(
        &self, name: &str, category: &str, object_id: Sha256HashValue
    ) -> Result<()> {
        let object_path = format!("objects/{:02x}/{}", object_id[0], hex::encode(&object_id[1..]));
        let category_path = format!("{}/{}", category, hex::encode(object_id));
        let ref_path = format!("{}/refs/{}", category, name);

        self.symlink(&ref_path, &category_path)?;
        self.symlink(&category_path, &object_path)?;
        Ok(())
    }

    fn symlink<P: AsRef<Path>>(&self, name: P, target: &str) -> Result<()> {
        let name = name.as_ref();
        let parent = name.parent()
            .expect("make_link() called for file directly in repo top-level");
        self.ensure_dir(parent)?;

        let mut target_path = PathBuf::new();
        for _ in parent.iter() {
            target_path.push("..");
        }
        target_path.push(target);

        Ok(symlinkat(target_path, &self.repository, name)?)
    }

    fn read_symlink_hashvalue(dirfd: &OwnedFd, name: &CStr) -> Result<Sha256HashValue> {
        let link_content = readlinkat(dirfd, name, [])?;
        let link_bytes = link_content.to_bytes();
        let link_size = link_bytes.len();
        // XXX: check correctness of leading ../?
        // XXX: or is that something for fsck?
        if link_size > 64 {
            let mut value = Sha256HashValue::EMPTY;
            hex::decode_to_slice(&link_bytes[link_size-64..link_size], &mut value)?;
            Ok(value)
        } else {
            bail!("symlink has wrong format")
        }
    }

    fn walk_symlinkdir(fd: OwnedFd, objects: &mut HashSet<Sha256HashValue>) -> Result<()> {
        for item in Dir::read_from(&fd)? {
            match item {
                Err(x) => Err(x)?,
                Ok(entry) => {
                    // NB: the underlying filesystem must support returning filetype via direntry
                    // that's a reasonable assumption, since it must also support fsverity...
                    match entry.file_type() {
                        FileType::Directory => {
                            let filename = entry.file_name();
                            if filename != c"." && filename != c".." {
                                let dirfd = openat(&fd, filename, OFlags::RDONLY, Mode::empty())?;
                                Repository::walk_symlinkdir(dirfd, objects)?;
                            }
                        },
                        FileType::Symlink => {
                            objects.insert(Repository::read_symlink_hashvalue(&fd, entry.file_name())?);
                        },
                        _ => {
                            bail!("Unexpected file type encountered");
                        },
                    }
                }
            }
        }

        Ok(())
    }

    fn openat(&self, name: &str, flags: OFlags) -> Result<OwnedFd> {
        Ok(openat(&self.repository, name, flags, Mode::empty())?)
    }

    fn gc_category(&self, category: &str) -> Result<HashSet<Sha256HashValue>> {
        let mut objects = HashSet::<Sha256HashValue>::new();

        let category_fd = self.openat(category, OFlags::RDONLY | OFlags::DIRECTORY)?;

        let refs = openat(&category_fd, "refs", OFlags::RDONLY | OFlags::DIRECTORY, Mode::empty())?;
        Repository::walk_symlinkdir(refs, &mut objects)?;

        for item in Dir::read_from(&category_fd)? {
            match item {
                Err(x) => Err(x)?,
                Ok(entry) => {
                    let filename = entry.file_name();
                    if filename != c"refs" && filename != c"." && filename != c".." {
                        if entry.file_type() != FileType::Symlink {
                            bail!("category directory contains non-symlink");
                        }
                        let mut value = Sha256HashValue::EMPTY;
                        hex::decode_to_slice(filename.to_bytes(), &mut value)?;

                        if !objects.contains(&value) {
                            println!("rm {}/{:?}", category, filename);
                        }
                    }
                }
            }
        }

        Ok(objects)
    }

    pub fn gc(&self) -> Result<()> {
        flock(&self.repository, FlockOperation::LockExclusive)?;

        let mut objects = HashSet::new();

        for object in self.gc_category("images")? {
            println!("{} lives as an image", hex::encode(object));
            objects.insert(object);

            // composefs-info mmaps the file, so pipes aren't normally OK but we pass the
            // underlying file directly, which works.
            let output = Command::new("composefs-info")
                .stdin(File::from(self.open_object(object)?))
                .args(["objects", "/proc/self/fd/0"])
                .output()?
                .stdout;

            if output.len() % 66 != 0 {
                bail!("composefs-info gave invalid output (wrong size)");
            }

            for line in output.chunks_exact(66) {
                if line[2] != b'/' || line[65] != b'\n' {
                    bail!("composefs-info gave invalid output");
                }
                let mut value = Sha256HashValue::EMPTY;
                hex::decode_to_slice(&line[0..2], &mut value[0..1])?;
                hex::decode_to_slice(&line[3..65], &mut value[1..32])?;
                println!("    with {}", hex::encode(value));
                objects.insert(value);
            }
        }

        for object in self.gc_category("streams")? {
            println!("{} lives as a stream", hex::encode(object));
            objects.insert(object);

            let file = File::from(self.open_object(object)?);
            let mut split_stream = zstd::stream::read::Decoder::new(file)?;
            splitstream_objects(
                &mut split_stream,
                |obj: Sha256HashValue| {
                    println!("   with {}", hex::encode(obj));
                    objects.insert(obj);
                }
            )?;
        }

        for first_byte in 0x0..=0xff {
            let dirfd = self.openat(&format!("objects/{first_byte:02x}"), OFlags::RDONLY | OFlags::DIRECTORY)?;
            for item in Dir::new(dirfd)? {
                match item {
                    Err(e) => Err(e)?,
                    Ok(entry) => {
                        let filename = entry.file_name();
                        if filename != c"." && filename != c".." {
                            let mut value = Sha256HashValue::EMPTY;
                            value[0] = first_byte;
                            hex::decode_to_slice(filename.to_bytes(), &mut value[1..])?;
                            if !objects.contains(&value) {
                                println!("rm objects/{first_byte:02x}/{filename:?}");
                            } else {
                                println!("# objects/{first_byte:02x}/{filename:?} lives");
                            }
                        }
                    }
                }
            }
        }

        Ok(flock(&self.repository, FlockOperation::LockShared)?)  // XXX: finally { } ?
    }

    pub fn fsck(&self) -> Result<()> {
        Ok(())
    }
}
