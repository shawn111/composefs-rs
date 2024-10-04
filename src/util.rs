use std::os::fd::{
    AsFd,
    AsRawFd,
};

pub fn proc_self_fd<A: AsFd>(fd: &A) -> String {
    format!("/proc/self/fd/{}", fd.as_fd().as_raw_fd())
}
