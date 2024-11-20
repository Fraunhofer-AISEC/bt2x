use crate::artifact::source::ArtifactSource;
use crate::error::Bt2XError;
use async_trait::async_trait;
use oci_distribution::client::{ClientConfig, ImageData};
use oci_distribution::secrets::RegistryAuth;
use sigstore::registry::OciReference;
use std::ops::Add;
use std::str::FromStr;
use tracing::debug;

pub struct OciSource {
    pub client: oci_distribution::Client,
    pub(crate) auth: RegistryAuth,
}

impl OciSource {
    pub fn new(config: ClientConfig, auth: RegistryAuth) -> Self {
        OciSource {
            auth,
            client: oci_distribution::Client::new(config),
        }
    }

    async fn pull_image(&mut self, image: &OciReference) -> Result<ImageData, Bt2XError> {
        debug!("pulling image at {image:?}");
        let image = oci_distribution::Reference::from_str(&image.whole()).unwrap();
        self.client
            .pull(
                &image,
                &self.auth,
                vec![
                    oci_distribution::manifest::WASM_LAYER_MEDIA_TYPE,
                    oci_distribution::manifest::WASM_CONFIG_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_MANIFEST_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_MANIFEST_LIST_MEDIA_TYPE,
                    oci_distribution::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE,
                    oci_distribution::manifest::OCI_IMAGE_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_CONFIG_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_DOCKER_CONFIG_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_LAYER_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_LAYER_GZIP_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_DOCKER_LAYER_TAR_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_LAYER_NONDISTRIBUTABLE_MEDIA_TYPE,
                    oci_distribution::manifest::IMAGE_LAYER_NONDISTRIBUTABLE_GZIP_MEDIA_TYPE,
                    "text/plain",
                    "application/octet-stream",
                ],
            )
            .await
            .map_err(|err| err.into())
    }
    async fn pull_blob(&mut self, image: &OciReference) -> Result<Vec<u8>, Bt2XError> {
        debug!("pulling blob at {image:?}");
        let digest = image
            .digest()
            .ok_or(Bt2XError::MissingDigestInOciReference(image.clone()))?;
        let image = OciReference::with_digest(
            image.registry().to_string(),
            image.repository().to_string(),
            digest.to_string(),
        );
        self.pull_image(&image)
            .await
            .and_then(|mut image| {
                image
                    .layers
                    .pop()
                    .ok_or(Bt2XError::MissingContainerImageLayers)
            })
            .map(|layer| layer.data)
    }
    async fn pull_bundle(&mut self, image: &OciReference) -> Result<Vec<u8>, Bt2XError> {
        debug!("pulling bundle at {image:?}");
        let digest = image
            .digest()
            .ok_or(Bt2XError::MissingDigestInOciReference(image.clone()))?;
        let image = OciReference::with_tag(
            image.registry().to_string(),
            image.repository().to_string(),
            digest.to_string().replace(':', "-").add(".bundle"),
        );
        debug!("{image}");
        self.pull_image(&image)
            .await
            .and_then(|mut image| {
                image
                    .layers
                    .pop()
                    .ok_or(Bt2XError::MissingContainerImageLayers)
            })
            .map(|layer| layer.data)
    }
}

pub struct OciImage {
    pub data: ImageData,
}

#[async_trait(? Send)]
impl ArtifactSource<Vec<u8>, OciReference> for OciSource {
    async fn get_artifact(&mut self, identifier: &OciReference) -> Result<Vec<u8>, Bt2XError> {
        identifier
            .digest()
            .ok_or(Bt2XError::MissingDigestInOciReference(identifier.clone()))?;
        self.pull_blob(identifier).await
    }

    async fn get_bundle(&mut self, identifier: &OciReference) -> Result<Vec<u8>, Bt2XError> {
        identifier
            .digest()
            .ok_or(Bt2XError::MissingDigestInOciReference(identifier.clone()))?;
        self.pull_bundle(identifier).await
    }
}
