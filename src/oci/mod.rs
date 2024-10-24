pub mod image;
pub mod tar;

use std::{
    io::Read,
    iter::zip,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use oci_spec::image::{
    Descriptor,
    ImageConfiguration,
    ImageManifest,
};
use containers_image_proxy::{
    ImageProxy,
    OpenedImage,
};
use tokio::io::AsyncReadExt;
use async_compression::tokio::bufread::GzipDecoder;

use crate::{
    fsverity::Sha256HashValue,
    repository::Repository,
    oci::tar::{
        get_entry,
        split_async,
    },
    splitstream::DigestMap,
    util::parse_sha256
};

pub fn import_layer(
    repo: &Repository, sha256: &Sha256HashValue, name: Option<&str>, tar_stream: &mut impl Read
) -> Result<Sha256HashValue> {
    repo.ensure_stream(sha256, |writer| tar::split(tar_stream, writer), name)
}

pub fn ls_layer(repo: &Repository, name: &str) -> Result<()> {
    let mut split_stream = repo.open_stream(name, None)?;

    while let Some(entry) = get_entry(&mut split_stream)? {
        println!("{}", entry);
    }

    Ok(())
}

struct ImageOp<'repo> {
    repo: &'repo Repository,
    proxy: ImageProxy,
    img: OpenedImage,
}

fn sha256_from_descriptor(descriptor: &Descriptor) -> Result<Sha256HashValue> {
    let Some(digest) = descriptor.as_digest_sha256() else {
        bail!("Descriptor in oci config is not sha256");
    };
    parse_sha256(digest)
}

fn sha256_from_digest(digest: &str) -> Result<Sha256HashValue> {
    match digest.strip_prefix("sha256:") {
        Some(rest) => parse_sha256(rest),
        None => bail!("Manifest has non-sha256 digest"),
    }
}

type ContentAndVerity = (Sha256HashValue, Sha256HashValue);

impl<'repo> ImageOp<'repo> {
    async fn new(repo: &'repo Repository, imgref: &str) -> Result<Self> {
        let proxy = containers_image_proxy::ImageProxy::new().await?;
        let img = proxy.open_image(imgref).await.context("Opening image")?;
        Ok(ImageOp { repo, proxy, img })
    }

    pub async fn ensure_layer(
        &self, layer_sha256: &Sha256HashValue, descriptor: &Descriptor
    ) -> Result<Sha256HashValue> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.

        dbg!(hex::encode(layer_sha256), descriptor);
        if let Some(layer_id) = self.repo.has_stream(layer_sha256)? {
            Ok(layer_id)
        } else {
            // Otherwise, we need to fetch it...
            let (blob_reader, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;
            let decoder = GzipDecoder::new(blob_reader);
            let mut splitstream = self.repo.create_stream(Some(*layer_sha256), None);
            split_async(decoder, &mut splitstream).await?;
            let layer_id = self.repo.write_stream(splitstream)?;
            driver.await?;
            Ok(layer_id)
        }
    }

    pub async fn ensure_config(
        &self, manifest_layers: &[Descriptor], descriptor: &Descriptor
    ) -> Result<ContentAndVerity> {
        dbg!("ensure_config", &self.img, manifest_layers, descriptor);

        let config_sha256 = sha256_from_descriptor(descriptor)?;
        if let Some(config_id) = self.repo.has_stream(&config_sha256)? {
            // We already got this config?  Nice.
            Ok((config_sha256, config_id))
        } else {
            // We need to add the config to the repo.  We need to parse the config and make sure we
            // have all of the layers first.
            let (mut blob_reader, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;
            let mut raw_config = vec![];
            let (a, b) = tokio::join!(blob_reader.read_to_end(&mut raw_config), driver);
            a?;
            b?;

            let config = ImageConfiguration::from_reader(raw_config.as_slice())?;

            let mut config_maps = DigestMap::new();
            for (mld, cld) in zip(manifest_layers, config.rootfs().diff_ids()) {
                let layer_sha256 = sha256_from_digest(cld)?;
                let layer_id = self.ensure_layer(&layer_sha256, mld).await?;
                config_maps.insert(&layer_sha256, &layer_id);
            }

            let mut splitstream = self.repo.create_stream(Some(config_sha256), Some(config_maps));
            splitstream.write_inline(&raw_config);
            let config_id = self.repo.write_stream(splitstream)?;

            Ok((config_sha256, config_id))
        }
    }

    pub async fn ensure_manifest(&self) -> Result<(Sha256HashValue, Sha256HashValue)> {
        dbg!("ensure_manifest", &self.img);

        let (manifest_digest, raw_manifest) = self.proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;

        let sha256 = sha256_from_digest(&manifest_digest)?;

        if let Some(id) = self.repo.has_stream(&sha256)? {
            // We already got this manifest?  Nice.
            Ok((sha256, id))
        } else {
            // We need to add the manifest to the repo.  We need to parse the manifest and make
            // sure we have the config first (which will also pull in the layers).
            let manifest = ImageManifest::from_reader(raw_manifest.as_slice())?;
            let config_descriptor = manifest.config();
            let layers = manifest.layers();
            let (config_sha256, config_id) = self.ensure_config(layers, config_descriptor).await?;
            println!("config sha256 {}", hex::encode(config_sha256));
            println!("config verity {}", hex::encode(config_id));

            let mut manifest_maps = DigestMap::new();
            manifest_maps.insert(&config_sha256, &config_id);
            let mut split_stream = self.repo.create_stream(Some(sha256), Some(manifest_maps));
            split_stream.write_inline(&raw_manifest);
            let id = self.repo.write_stream(split_stream)?;
            Ok((sha256, id))
        }
    }
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
pub async fn pull(
    repo: &Repository,
    imgref: &str,
    _name: Option<&str>,
) -> Result<()> {
    let op = ImageOp::new(repo, imgref).await?;
    let (sha256, id) = op.ensure_manifest().await?;
    println!("manifest sha256 {}", hex::encode(sha256));
    println!("manifest verity {}", hex::encode(id));
    Ok(())
}
