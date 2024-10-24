use std::path::PathBuf;

use clap::Parser;

use composefs_experiments::mount::MountOptions;

/// mount a composefs
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg()]
    image: String,

    #[arg()]
    mountpoint: String,

    #[arg(short, long)]
    basedir: PathBuf,

    #[arg(short, long)]
    digest: Option<String>,
}

fn main() {
    let args = Args::parse();

    let mut options = MountOptions::new(&args.image, &args.basedir);
    if let Some(expected) = &args.digest {
        options.set_digest(expected);
    }
    options.set_require_verity();

    if let Err(x) = options.mount(&args.mountpoint) {
        println!("err {}", x);
    }
}
