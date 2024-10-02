use std::ffi::CString;

pub struct TempDir {
    pub path: CString,
}

impl TempDir {
    pub fn new() -> std::io::Result<TempDir>{
        let mut template = CString::from(c"/tmp/composefs.upper.XXXXXX");

        unsafe {
            let raw = template.into_raw();
            let result = libc::mkdtemp(raw);
            template = CString::from_raw(raw);
            if result.is_null() {
                return Err(std::io::Error::last_os_error());
            }
        }

        return Ok(TempDir { path: template });
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        unsafe {
            libc::rmdir(self.path.as_ptr());
        }
    }
}
