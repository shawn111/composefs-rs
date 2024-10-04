use std::path::PathBuf;
use std::io::ErrorKind;
use std::os::fd::OwnedFd;

use rustix::fs::{
    CWD,
    linkat,
    Access,
    AtFlags,
    Mode,
    OFlags,
    accessat,
    mkdirat,
    open,
    openat,
    fdatasync,
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
    util::proc_self_fd,
};

pub struct Repository {
    repository: OwnedFd,
    objects: OwnedFd,
}

impl Repository {
    pub fn open(path: &str) -> std::io::Result<Repository> {
        let repository = open(path, OFlags::PATH, Mode::empty())?;
        let objects = openat(&repository, "objects", OFlags::PATH, Mode::empty())?;

        Ok(Repository { repository, objects })
    }

    pub fn ensure_data(&self, data: &[u8]) -> std::io::Result<Sha256HashValue> {
        let digest = FsVerityHasher::hash(data);
        let dir = PathBuf::from(format!("{:02x}", digest[0]));
        let file = dir.join(hex::encode(&digest[1..]));

        if accessat(&self.objects, &file, Access::READ_OK, AtFlags::empty()) == Ok(()) {
            return Ok(digest);
        }

        if let Err(err) = mkdirat(&self.objects, &dir, 0o777.into()) {
            if err.kind() != ErrorKind::AlreadyExists {
                return Err(err.into());
            }
        }

        let fd = openat(&self.objects, &dir,
            OFlags::RDWR | OFlags::CLOEXEC | OFlags::TMPFILE, 0o666.into()
        )?;

        rustix::io::write(&fd, data)?;  // TODO: no write_all() here...

        fdatasync(&fd)?;

        // We can't enable verity with an open writable fd, so re-open and close the old one.
        let ro_fd = open(proc_self_fd(&fd), OFlags::RDONLY, Mode::empty())?;
        drop(fd);

        fs_ioc_enable_verity::<&OwnedFd, Sha256HashValue>(&ro_fd)?;

        // double-check
        let measured_digest: Sha256HashValue = fs_ioc_measure_verity(&ro_fd)?;
        assert!(measured_digest == digest);

        if let Err(err) = linkat(CWD, proc_self_fd(&ro_fd), &self.objects, file, AtFlags::SYMLINK_FOLLOW) {
            if err.kind() != ErrorKind::AlreadyExists {
                return Err(err.into());
            }
        }

        drop(ro_fd);
        Ok(digest)
    }
}
