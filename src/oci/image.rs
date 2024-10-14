use std::{
    ffi::OsStr,
    io::Read,
    os::unix::ffi::OsStrExt,
    process::{
        Command,
        Stdio
    },
};

use anyhow::{
    Result,
    bail,
};
use crate::{
    dumpfile::write_dumpfile,
    fsverity::Sha256HashValue,
    image::{
        FileSystem,
        Leaf,
    },
    oci,
    repository::Repository,
    splitstream::SplitStreamReader,
};

fn is_whiteout(name: &OsStr) -> Option<&OsStr> {
    let bytes = name.as_bytes();
    if bytes.len() > 4 && &bytes[0..4] == b".wh." {
        Some(OsStr::from_bytes(&bytes[4..]))
    } else {
        None
    }
}

pub fn process_entry(filesystem: &mut FileSystem, entry: oci::tar::TarEntry) -> Result<()> {
    if let Some(filename) = entry.path.file_name() {
        if let Some(whiteout) = is_whiteout(filename) {
            filesystem.remove(&entry.path.parent().unwrap().join(whiteout))?;
        } else {
            match entry.item {
                oci::tar::TarItem::Directory => {
                    filesystem.mkdir(&entry.path, entry.stat)?;
                },
                oci::tar::TarItem::Leaf(content) => {
                    filesystem.insert(&entry.path, Leaf { stat: entry.stat, content })?;
                },
                oci::tar::TarItem::Hardlink(target) => {
                    filesystem.hardlink(&entry.path, &target)?;
                },
            }
        }
    } else {
        bail!("Invalid filename");
    }
    Ok(())
}

pub fn compose_filesystem(repo: &Repository, layers: &[String]) -> Result<FileSystem> {
    let mut filesystem = FileSystem::new();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer)?;
        let mut reader = SplitStreamReader::new(&mut split_stream);
        while let Some(entry) = oci::tar::get_entry(&mut reader)? {
           process_entry(&mut filesystem, entry)?;
        }
    }

    Ok(filesystem)
}

pub fn create_dumpfile(repo: &Repository, layers: &[String]) -> Result<()> {
    let filesystem = compose_filesystem(repo, layers)?;
    let mut stdout = std::io::stdout();
    write_dumpfile(&mut stdout, &filesystem)?;
    Ok(())
}

pub fn create_image(repo: &Repository, name: &str, layers: &Vec<String>) -> Result<Sha256HashValue> {
    let mut filesystem = FileSystem::new();

    for layer in layers {
        let mut split_stream = repo.open_stream(layer)?;
        let mut reader = SplitStreamReader::new(&mut split_stream);
        while let Some(entry) = oci::tar::get_entry(&mut reader)? {
           process_entry(&mut filesystem, entry)?;
        }
    }

    let mut mkcomposefs = Command::new("mkcomposefs")
        .args(["--from-file", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let mut stdin = mkcomposefs.stdin.take().unwrap();
    write_dumpfile(&mut stdin, &filesystem)?;
    drop(stdin);

    let mut stdout = mkcomposefs.stdout.take().unwrap();
    let mut image = vec![];
    stdout.read_to_end(&mut image)?;
    drop(stdout);

    if !mkcomposefs.wait()?.success() {
        bail!("mkcomposefs failed");
    };

    repo.write_image(name, &image)
}
