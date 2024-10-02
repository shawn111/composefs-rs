mod tmpdir;

use rustix::mount::{
    FsMountFlags,
    FsOpenFlags,
    MountAttrFlags,
    MoveMountFlags,
    UnmountFlags,
    fsconfig_create,
    fsconfig_set_string,
    fsmount,
    fsopen,
    move_mount,
    unmount,
};
use std::os::fd::{
    OwnedFd,
    BorrowedFd,
    AsFd
};

struct FsHandle {
    pub fd: OwnedFd,
}

impl AsFd for FsHandle {
    fn as_fd(&self) -> BorrowedFd {
        return self.fd.as_fd();
    }
}

impl Drop for FsHandle {
    fn drop(&mut self) {
        let mut buffer = [0u8; 1024];
        match rustix::io::read(&self.fd, &mut buffer) {
            Err(_) => return, // ENODATA, among others?
            Ok(0) => return,
            Ok(size) => eprintln!("{}", String::from_utf8(buffer[0..size].to_vec()).unwrap()),
        }
    }
}

struct TmpMount {
    pub dir: tmpdir::TempDir,
}

impl TmpMount {
    pub fn mount(fs: BorrowedFd) -> std::io::Result<TmpMount> {
        let tmp = tmpdir::TempDir::new()?;
        let mnt = fsmount(fs, FsMountFlags::FSMOUNT_CLOEXEC, MountAttrFlags::empty())?;
        move_mount(mnt.as_fd(), "", rustix::fs::CWD, &tmp.path, MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)?;
        Ok(TmpMount { dir: tmp })
    }
}

impl Drop for TmpMount {
    fn drop(&mut self) {
        unmount(&self.dir.path, UnmountFlags::DETACH)
            .expect("umount(MNT_DETACH) failed");
    }
}

fn mount() -> std::io::Result<()> {
    let erofs = FsHandle { fd: fsopen("erofs", FsOpenFlags::FSOPEN_CLOEXEC)? };
    fsconfig_set_string(erofs.as_fd(), "source", "/home/lis/src/mountcfs/cfs")?;
    fsconfig_create(erofs.as_fd())?;

    let overlayfs = FsHandle { fd: fsopen("overlay", FsOpenFlags::FSOPEN_CLOEXEC)? };
    //fsconfig_set_flag(overlayfs.as_fd(), "ro")?;
    fsconfig_set_string(overlayfs.as_fd(), "metacopy", "on")?;
    fsconfig_set_string(overlayfs.as_fd(), "redirect_dir", "on")?;

    // unfortunately we can't do this via the fd: we need a tmpdir mountpoint
    let tmp = TmpMount::mount(erofs.as_fd())?;  // NB: must live until the "create" operation
    fsconfig_set_string(overlayfs.as_fd(), "lowerdir+", &tmp.dir.path)?;
    fsconfig_set_string(overlayfs.as_fd(), "datadir+", "/home/lis/src/mountcfs/digest")?;
    fsconfig_create(overlayfs.as_fd())?;

    let bzzt = fsmount(overlayfs.as_fd(), FsMountFlags::FSMOUNT_CLOEXEC, MountAttrFlags::empty())?;
    move_mount(bzzt.as_fd(), "", rustix::fs::CWD, "mnt", MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH)?;

    Ok(())
}

fn main() {
    if let Err(x) = mount() {
        println!("err {}", x);
    }
}
