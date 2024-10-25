pub mod image;
pub mod tar;

use std::{io::Read, iter::zip};

use anyhow::{bail, Context, Result};
use async_compression::tokio::bufread::GzipDecoder;
use containers_image_proxy::{ImageProxy, ImageProxyConfig, OpenedImage};
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use oci_spec::image::{Descriptor, ImageConfiguration, ImageManifest};
use tokio::io::AsyncReadExt;

use crate::{
    fsverity::Sha256HashValue,
    oci::tar::{get_entry, split_async},
    repository::Repository,
    splitstream::DigestMap,
    util::parse_sha256,
};

pub fn import_layer(
    repo: &Repository,
    sha256: &Sha256HashValue,
    name: Option<&str>,
    tar_stream: &mut impl Read,
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
    progress: MultiProgress,
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
        let config = ImageProxyConfig {
            // auth_anonymous: true, debug: true, insecure_skip_tls_verification: Some(true),
            ..ImageProxyConfig::default()
        };
        let proxy = containers_image_proxy::ImageProxy::new_with_config(config).await?;
        let img = proxy.open_image(imgref).await.context("Opening image")?;
        let progress = MultiProgress::new();
        Ok(ImageOp {
            repo,
            proxy,
            img,
            progress,
        })
    }

    pub async fn ensure_layer(
        &self,
        layer_sha256: &Sha256HashValue,
        descriptor: &Descriptor,
    ) -> Result<Sha256HashValue> {
        // We need to use the per_manifest descriptor to download the compressed layer but it gets
        // stored in the repository via the per_config descriptor.  Our return value is the
        // fsverity digest for the corresponding splitstream.

        if let Some(layer_id) = self.repo.has_stream(layer_sha256)? {
            self.progress
                .println(format!("Already have layer {}", hex::encode(layer_sha256)))?;
            Ok(layer_id)
        } else {
            // Otherwise, we need to fetch it...
            let (blob_reader, driver) = self.proxy.get_descriptor(&self.img, descriptor).await?;
            let bar = self.progress.add(ProgressBar::new(descriptor.size()));
            bar.set_style(ProgressStyle::with_template("[eta {eta}] {bar:40.cyan/blue} {decimal_bytes:>7}/{decimal_total_bytes:7} {msg}")
                .unwrap()
                .progress_chars("##-"));
            let progress = bar.wrap_async_read(blob_reader);
            self.progress
                .println(format!("Fetching layer {}", hex::encode(layer_sha256)))?;
            let decoder = GzipDecoder::new(progress);
            let mut splitstream = self.repo.create_stream(Some(*layer_sha256), None);
            split_async(decoder, &mut splitstream).await?;
            let layer_id = self.repo.write_stream(splitstream, None)?;
            driver.await?;
            Ok(layer_id)
        }
    }

    pub async fn ensure_config(
        &self,
        manifest_layers: &[Descriptor],
        descriptor: &Descriptor,
    ) -> Result<ContentAndVerity> {
        let config_sha256 = sha256_from_descriptor(descriptor)?;
        if let Some(config_id) = self.repo.has_stream(&config_sha256)? {
            // We already got this config?  Nice.
            self.progress.println(format!(
                "Already have container layer {}",
                hex::encode(config_sha256)
            ))?;
            Ok((config_sha256, config_id))
        } else {
            // We need to add the config to the repo.  We need to parse the config and make sure we
            // have all of the layers first.
            //
            self.progress
                .println(format!("Fetching config {}", hex::encode(config_sha256)))?;
            let raw_config = self.proxy.fetch_config_raw(&self.img).await?;
            let config = ImageConfiguration::from_reader(raw_config.as_slice())?;

            let mut config_maps = DigestMap::new();
            for (mld, cld) in zip(manifest_layers, config.rootfs().diff_ids()) {
                let layer_sha256 = sha256_from_digest(cld)?;
                let layer_id = self
                    .ensure_layer(&layer_sha256, mld)
                    .await
                    .with_context(|| format!("Failed to fetch layer {cld} via {mld:?}"))?;
                config_maps.insert(&layer_sha256, &layer_id);
            }

            let mut splitstream = self
                .repo
                .create_stream(Some(config_sha256), Some(config_maps));
            splitstream.write_inline(&raw_config);
            let config_id = self.repo.write_stream(splitstream, None)?;

            Ok((config_sha256, config_id))
        }
    }

    pub async fn pull(&self) -> Result<(Sha256HashValue, Sha256HashValue)> {
        let (_manifest_digest, raw_manifest) = self
            .proxy
            .fetch_manifest_raw_oci(&self.img)
            .await
            .context("Fetching manifest")?;

        // We need to add the manifest to the repo.  We need to parse the manifest and make
        // sure we have the config first (which will also pull in the layers).
        let manifest = ImageManifest::from_reader(raw_manifest.as_slice())?;
        let config_descriptor = manifest.config();
        let layers = manifest.layers();
        self.ensure_config(layers, config_descriptor)
            .await
            .with_context(|| format!("Failed to pull config {config_descriptor:?}"))
    }
}

/// Pull the target image, and add the provided tag. If this is a mountable
/// image (i.e. not an artifact), it is *not* unpacked by default.
pub async fn pull(repo: &Repository, imgref: &str, reference: Option<&str>) -> Result<()> {
    let op = ImageOp::new(repo, imgref).await?;
    let (sha256, id) = op
        .pull()
        .await
        .with_context(|| format!("Unable to pull container image {imgref}"))?;

    if let Some(name) = reference {
        repo.name_stream(sha256, name)?;
    }
    println!("sha256 {}", hex::encode(sha256));
    println!("verity {}", hex::encode(id));
    Ok(())
}
