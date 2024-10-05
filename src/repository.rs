use std::io::ErrorKind;
use std::io::{
    Read,
    Write,
};
use std::os::fd::OwnedFd;
use std::path::{
    Path,
    PathBuf,
};

use anyhow::Result;
use rustix::fs::{
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
    symlinkat,
};

use crate::{
    fsverity::{
        Sha256HashValue,
        digest::FsVerityHasher,
        ioctl::{
            fs_ioc_enable_verity,
            fs_ioc_measure_verity,
        },
    },
    tar,
    util::proc_self_fd,
};

pub struct Repository {
    repository: OwnedFd,
}

impl Drop for Repository {
    fn drop(&mut self) {
        flock(&self.repository, FlockOperation::Unlock)
            .expect("repository unlock failed");
    }
}

impl Repository {
    pub fn open_fd(repository: OwnedFd) -> Result<Repository> {
        flock(&repository, FlockOperation::LockShared)?;
        Ok(Repository { repository })
    }

    pub fn open_path<P: rustix::path::Arg>(path: P) -> Result<Repository> {
        // O_PATH isn't enough because flock()
        Repository::open_fd(open(path, OFlags::RDONLY, Mode::empty())?)
    }

    pub fn open_default() -> Result<Repository> {
        let home = PathBuf::from(std::env::var("HOME").expect("$HOME must be set"));
        Repository::open_path(home.join(".var/lib/composefs"))
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

    pub fn merge_splitstream<W: Write>(&self, name: &str, stream: &mut W) -> Result<()> {
        Ok(())
    }

    pub fn import_tar<R: Read>(&self, name: &str, tar_stream: &mut R) -> Result<()> {
        let mut split_stream = zstd::stream::write::Encoder::new(vec![], 0)?;

        tar::split(
            tar_stream,
            &mut split_stream,
            |data: &[u8]| -> Result<Sha256HashValue> {
                self.ensure_object(data)
        })?;

        let object_id = self.ensure_object(&split_stream.finish()?)?;
        self.link_ref(name, "streams", object_id)
    }

    fn link_ref(
        &self, name: &str, category: &str, object_id: Sha256HashValue
    ) -> Result<()> {
        let object_path = format!("objects/{:02x}/{}", object_id[0], hex::encode(&object_id[1..]));
        let category_path = format!("{}/{}", category, hex::encode(&object_id));
        let ref_path = format!("refs/{}", name);

        self.symlink(&ref_path, &category_path)?;
        self.symlink(&category_path, &object_path)?;
        Ok(())
    }

    fn symlink<P: AsRef<Path>>(&self, name: P, target: &str) -> Result<()> {
        let name = name.as_ref();
        let parent = name.parent()
            .expect("make_link() called for file directly in repo top-level");
        self.ensure_dir(&parent)?;

        let mut target_path = PathBuf::new();
        for _ in parent.iter() {
            target_path.push("..");
        }
        target_path.push(target);

        Ok(symlinkat(target_path, &self.repository, name)?)
    }

    pub fn gc(&self) -> Result<()> {
        flock(&self.repository, FlockOperation::LockExclusive)?;

        // TODO: GC

        Ok(flock(&self.repository, FlockOperation::LockShared)?)  // XXX: finally { } ?
    }

    pub fn fsck(&self) -> Result<()> {
        Ok(())
    }
}
