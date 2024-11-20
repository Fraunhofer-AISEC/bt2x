use crate::artifact::source::ArtifactSource;
use anyhow::Result;
use async_trait::async_trait;

/// Abstraction trait of a verifier.
#[async_trait(? Send)] // this is to avoid issues with Box<dyn ...>, not sure if this the correct way to do this
pub trait Verifier<T, S, I, C> {
    /// Verify the the artifact specified by the identifier fetched from the source under the given constraints.
    /// Returns a verified [[Artifact]].
    async fn verify(
        &mut self,
        source: &mut S,
        identifier: &I,
        constraints: &C,
    ) -> Result<Artifact<T>>
    where
        S: ArtifactSource<T, I>;
}

/// There are different kinds of artifacts that can be verified.
#[derive(Debug)]
pub enum Artifact<T> {
    /// Raw binary without a bundled signature.
    Binary(T),
    /// Binary that is bundled with a signature.
    BundledBinary { binary: T, bundle: T },
}

#[cfg(feature = "bt")]
pub mod bt;
