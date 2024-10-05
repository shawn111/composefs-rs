use anyhow::Result;

use composefs_experiments::{
    fsverity::Sha256HashValue,
    tar::split,
    repository::Repository,
};

// produce a splitstream from a tar
fn main() {
    let repo = Repository::open_default().expect("open cfs-repo");

    split(
        &mut std::io::stdin(),
        &mut std::io::stdout(),
        |data: &[u8]| -> Result<Sha256HashValue> {
            repo.ensure_object(&data)
        }
    ).expect("split");
}
