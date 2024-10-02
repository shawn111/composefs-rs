use rand::distributions::{Alphanumeric, DistString};
use std::path::PathBuf;

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new() -> std::io::Result<TempDir>{
        let tmp = PathBuf::from("/tmp");

        for _ in 0 .. 26*26*26 {  // this is how many times glibc tries
            let suffix = Alphanumeric.sample_string(&mut rand::thread_rng(), 6);
            let path = tmp.join(format!("composefs.{}", suffix));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(TempDir { path }),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e)
            }
        }

        Err(std::io::Error::from(std::io::ErrorKind::AlreadyExists))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        std::fs::remove_dir(&self.path).expect("can't remove tempdir");
    }
}
