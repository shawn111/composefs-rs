use std::path::PathBuf;

use clap::{Parser, Subcommand};

use composefs_experiments::repository::Repository;


/// cfsctl
#[derive(Debug, Parser)]
#[clap(name = "cfsctl", version)]
pub struct App {
    #[clap(long)]
    repo: Option<String>,

    #[clap(subcommand)]
    cmd: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Take a transaction lock on the repository.
    /// This prevents garbage collection from occurring.
    Transaction,
    /// Reconstitutes a split stream and writes it to stdout
    Cat {
        reference: String,
    },
    /// Imports a composefs image (unsafe!)
    ImportImage {
        reference: String,
    },
    /// Stores a tar file as a splitstream in the repository.
    ImportTar {
        reference: String,
        tarfile: Option<PathBuf>,
    },
    /// Mounts a composefs
    Mount {
        name: String,
        mountpoint: String,
    },
}

fn main() {
    let args = App::parse();

    let repo = match args.repo {
        None => Repository::open_default(),
        Some(path) => Repository::open_path(path),
    }.expect("bzzt");

    match args.cmd {
        Command::Transaction => {
            // just wait for ^C
            loop {
                std::thread::park();
            }
        },
        Command::Cat { reference } => {
            repo.merge_splitstream(&reference, &mut std::io::stdout()).expect("merge");
        },
        Command::ImportImage { reference, } => {
            repo.import_image(&reference, &mut std::io::stdin()).expect("image-import");
        },
        Command::ImportTar { reference, tarfile: _ } => {
            repo.import_tar(&reference, &mut std::io::stdin()).expect("tar-import");
        },
        Command::Mount { name, mountpoint } => {
            repo.mount(&name, &mountpoint).expect("mount");
        },
    }
}
