use std::path::PathBuf;
use anyhow::Result;
use clap::{Parser, Subcommand};

use composefs_experiments::{
    fsverity::{
        FsVerityHashValue,
        Sha256HashValue,
    },
    oci,
    repository::Repository,
};


/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long, group="repopath")]
    repo: Option<PathBuf>,
    #[clap(long, group="repopath")]
    user: bool,
    #[clap(long, group="repopath")]
    system: bool,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum OciCommand {
    /// Stores a tar file as a splitstream in the repository.
    ImportLayer {
        name: String,
        #[clap(long)]
        sha256: Option<String>,
    },
    /// Lists the contents of a tar stream
    LsLayer {
        /// the name of the stream
        name: String,
    },
    CreateImage {
        layers: Vec<String>,
    },
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        /// the name of the stream to cat, either a sha256 digest or prefixed with 'ref/'
        name: String,
    },
    /// Perform garbage collection
    GC,
    /// Imports a composefs image (unsafe!)
    ImportImage {
        reference: String,
    },
    /// Commands for dealing with OCI layers
    Oci {
        #[clap(subcommand)]
        cmd: OciCommand
    },
    /// Mounts a composefs, possibly enforcing fsverity of the image
    Mount {
        /// the name of the image to mount, either a sha256 digest or prefixed with 'ref/'
        name: String,
        /// the mountpoint
        mountpoint: String,
    },
}

fn main() -> Result<()> {
    let args = App::parse();

    let repo = (
        if let Some(path) = args.repo {
            Repository::open_path(path)
        } else if args.system {
            Repository::open_system()
        } else if args.user {
            Repository::open_user()
        } else if rustix::process::getuid().is_root() {
            Repository::open_system()
        } else {
            Repository::open_user()
        }
    )?;

    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        },
        Command::Cat { name } => {
            repo.merge_splitstream(&name, &mut std::io::stdout())?;
        },
        Command::ImportImage { reference, } => {
            let image_id = repo.import_image(&reference, &mut std::io::stdin())?;
            println!("{}", hex::encode(image_id));
        },
        Command::Oci{ cmd: oci_cmd } => match oci_cmd {
            OciCommand::ImportLayer { name, sha256 } => {
                if let Some(digest) = sha256 {
                    let mut value = Sha256HashValue::EMPTY;
                    hex::decode_to_slice(digest, &mut value)?;
                    oci::import_layer_by_sha256(&repo, &name, &mut std::io::stdin(), value)?;
                } else {
                    let stream_id = oci::import_layer(&repo, &name, &mut std::io::stdin())?;
                    println!("{}", hex::encode(stream_id));
                }
            },
            OciCommand::LsLayer { name } => {
                oci::ls_layer(&repo, &name)?;
            },
            OciCommand::CreateImage { layers } => {
                oci::image::create_image(&repo, &layers)?;
            },
        }
        Command::Mount { name, mountpoint } => {
            repo.mount(&name, &mountpoint)?;
        },
        Command::GC => {
            repo.gc()?;
        }
    }
    Ok(())
}
