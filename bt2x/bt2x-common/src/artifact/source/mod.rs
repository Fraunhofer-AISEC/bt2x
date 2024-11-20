use crate::error::Bt2XError;
use async_trait::async_trait;

#[async_trait(? Send)]
pub trait ArtifactSource<Artifact, Identifier> {
    async fn get_artifact(&mut self, identifier: &Identifier) -> Result<Artifact, Bt2XError>;

    async fn get_bundle(&mut self, identifier: &Identifier) -> Result<Artifact, Bt2XError>;
}

#[cfg(feature = "oci")]
pub mod oci;

#[cfg(feature = "bt")]
pub mod bundle;
