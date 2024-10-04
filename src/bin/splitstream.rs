use composefs_experiments::{
    fsverity::Sha256HashValue,
    tar::split,
    repository::Repository,
};

// produce a splitstream from a tar
fn main() {
    let repo = Repository::open("/home/lis/.var/lib/composefs").expect("open cfs-repo");

    split(
        &mut std::io::stdin(),
        &mut std::io::stdout(),
        |data: Vec<u8>| -> std::io::Result<Sha256HashValue> {
            repo.ensure_data(&data)
        }
    ).expect("split");
}
