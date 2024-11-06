use std::{ffi::OsStr, mem::MaybeUninit, path::Path};

use anyhow::Result;
use rustix::{
    fd::OwnedFd,
    fs::{fdatasync, linkat, mkdirat, mknodat, openat, symlinkat, AtFlags, FileType, OFlags, CWD},
    io::{read_uninit, write, Errno},
};

use crate::{
    image::{DirEnt, Directory, Inode, Leaf, LeafContent, Stat},
    repository::Repository,
    util::proc_self_fd,
};

fn set_file_contents(dirfd: &OwnedFd, name: &OsStr, stat: &Stat, data: &[u8]) -> Result<()> {
    match openat(
        dirfd,
        ".",
        OFlags::WRONLY | OFlags::TMPFILE,
        stat.st_mode.into(),
    ) {
        Ok(tmp) => {
            write(&tmp, data)?; // TODO: make this better
            fdatasync(&tmp)?;
            linkat(
                CWD,
                proc_self_fd(&tmp),
                dirfd,
                name,
                AtFlags::SYMLINK_FOLLOW,
            )?;
        }
        Err(Errno::OPNOTSUPP) => {
            // vfat? yolo...
            let fd = openat(dirfd, name, OFlags::CREATE | OFlags::WRONLY, stat.st_mode.into())?;
            write(&fd, data)?;
            fdatasync(&fd)?;
        }
        Err(e) => Err(e)?,
    }
    Ok(())
}

fn write_directory(
    dir: &Directory,
    dirfd: &OwnedFd,
    name: &OsStr,
    repo: &Repository,
) -> Result<()> {
    match mkdirat(dirfd, name, dir.stat.st_mode.into()) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => Err(e)?,
    }

    let fd = openat(dirfd, name, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}

fn write_leaf(leaf: &Leaf, dirfd: &OwnedFd, name: &OsStr, repo: &Repository) -> Result<()> {
    let mode = leaf.stat.st_mode.into();

    match leaf.content {
        LeafContent::InlineFile(ref data) => set_file_contents(dirfd, name, &leaf.stat, data)?,
        LeafContent::ExternalFile(ref id, size) => {
            let object = repo.open_object(id)?;
            // TODO: make this better.  At least needs to be EINTR-safe.  Could even do reflink in some cases...
            let mut buffer = vec![MaybeUninit::uninit(); size as usize];
            let (data, _) = read_uninit(object, &mut buffer)?;
            set_file_contents(dirfd, name, &leaf.stat, data)?;
        }
        LeafContent::BlockDevice(rdev) => mknodat(dirfd, name, FileType::BlockDevice, mode, rdev)?,
        LeafContent::CharacterDevice(rdev) => {
            mknodat(dirfd, name, FileType::CharacterDevice, mode, rdev)?
        }
        LeafContent::Socket => mknodat(dirfd, name, FileType::Socket, mode, 0)?,
        LeafContent::Fifo => mknodat(dirfd, name, FileType::Fifo, mode, 0)?,
        LeafContent::Symlink(ref target) => symlinkat(target, dirfd, name)?,
    }

    Ok(())
}

fn write_directory_contents(dir: &Directory, fd: &OwnedFd, repo: &Repository) -> Result<()> {
    for DirEnt { name, inode } in &dir.entries {
        match inode {
            Inode::Directory(ref dir) => write_directory(dir, fd, name, repo),
            Inode::Leaf(ref leaf) => write_leaf(leaf, fd, name, repo),
        }?;
    }

    Ok(())
}

pub fn write_to_path(repo: &Repository, dir: &Directory, output_dir: &Path) -> Result<()> {
    let fd = openat(CWD, output_dir, OFlags::PATH | OFlags::DIRECTORY, 0.into())?;
    write_directory_contents(dir, &fd, repo)
}
