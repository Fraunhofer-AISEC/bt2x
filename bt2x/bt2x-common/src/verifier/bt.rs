#[cfg(feature = "oci")]
use crate::artifact::source::oci::OciSource;
use crate::error::Bt2XError;
use anyhow::{anyhow, Context};
use async_trait::async_trait;
use oci_distribution::secrets::RegistryAuth;
use sigstore::cosign::verification_constraint::{
    VerificationConstraint, VerificationConstraintVec,
};
use sigstore::cosign::{
    verify_constraints, Client as CosignClient, CosignCapabilities, SignatureLayer,
};
use sigstore::registry::OciReference;
use std::fmt::Debug;
use tracing::debug;
use url::Url;

use crate::merkle::{MerkleProofVerifier, Rfc6269Default, Rfc6269HasherTrait};
use crate::verifier::{Artifact, Verifier};

use typed_builder::TypedBuilder as Builder;

use sigstore::crypto::{CosignVerificationKey, SigningScheme};
use sigstore::registry::Auth;

use anyhow::Result;

use digest::Output;

use crate::artifact::source::ArtifactSource;
use crate::gossip::send_checkpoint;
use crate::rekor::RekorClient;
use crate::verifier::Artifact::{Binary, BundledBinary};
use olpc_cjson::CanonicalFormatter;
use serde::Serialize;
use sigstore::cosign::bundle::{PayloadBody, SignedArtifactBundle};
use sigstore::rekor::models::log_entry::{Body, InclusionProof};
use sigstore::rekor::models::{ConsistencyProof, LogEntry};

/// Runs verification based on the given Sigstore keys.
#[derive(Builder)]
pub struct BinaryTransparencyVerifier {
    rekor_client: RekorClient,
    cosign_client: CosignClient,
    keys: SigstoreKeys,
    monitors: Vec<Url>,
}

#[derive(Builder, Debug)]
pub struct SigstoreKeys {
    rekor_pub_key: String,
    #[builder(default, setter(strip_option))]
    fulcio_cert: Option<String>,
    #[builder(default, setter(strip_option))]
    ct_log_key: Option<String>,
}

#[async_trait(? Send)]
#[cfg(feature = "oci")]
impl Verifier<Vec<u8>, OciSource, OciReference, VerificationConstraintVec>
    for BinaryTransparencyVerifier
{
    async fn verify(
        &mut self,
        source: &mut OciSource,
        identifier: &OciReference,
        constraints: &VerificationConstraintVec,
    ) -> Result<Artifact<Vec<u8>>> {
        let target = identifier;
        debug!("attempting to verify: {target}");
        let auth = match &source.auth {
            RegistryAuth::Anonymous => Auth::Anonymous,
            RegistryAuth::Basic(s1, s2) => Auth::Basic(s1.clone(), s2.clone()),
        };
        let (cosign_image, source_digest) =
            match self.cosign_client.triangulate(target, &auth).await {
                Ok((cosign_image, source_digest)) => (cosign_image, source_digest),
                Err(err) => return Err(anyhow!("failed to get cosign image for {target} ({err})")),
            };
        let source_image_with_digest = OciReference::with_digest(
            target.registry().to_string(),
            target.repository().to_string(),
            source_digest.to_string(),
        );

        debug!("source image is: {source_image_with_digest}");
        debug!("cosign image is: {cosign_image}");

        let signature_layers = match self
            .cosign_client
            .trusted_signature_layers(&auth, &source_digest, &cosign_image)
            .await
        {
            Ok(layers) => layers,
            Err(err) => return Err(anyhow!("Failed to get signature layers {err}")),
        };

        verify_constraints(&signature_layers, constraints.iter()).map_err(|err| {
            debug!("verifying contraints failed {err}");
            anyhow!("verification of constraint(s) failed {err}")
        })?;
        debug!("pulling artifact");
        let rekor_bundle = if let [SignatureLayer {
            bundle: Some(bundle),
            ..
        }] = &signature_layers[..]
        {
            Ok(bundle)
        } else {
            Err(anyhow!(
                "failed to extract bundle and signature from signature layerslayers"
            ))
        }?;

        debug!("successfully passed all checks providing by signature layers ...");
        // needs log id of first entry
        let online_entry = self
            .rekor_client
            .get_log_entry(rekor_bundle.payload.log_index as u64)
            .await
            .map_err(|err| anyhow!("failed to get online entry {err}"))?;

        // Gossip entry to monitor
        let checkpoint = online_entry
            .verification
            .inclusion_proof
            .as_ref()
            .ok_or(anyhow!("missing inclusion proof"))
            .and_then(|ip| ip.checkpoint.parse().context("failed to parse checkpoint"))?;

        for url in &self.monitors {
            send_checkpoint(url, &checkpoint).await.map_err(|err| {
                anyhow!("failed to get consistency confirmation from monitor {err:?}")
            })?;
        }

        let constraints: VerificationConstraintVec =
            vec![Box::new(InclusionVerifier { online_entry })];
        verify_constraints(&signature_layers, constraints.iter())
            .map_err(|err| anyhow!("online verification failed {err}"))?;
        debug!(
            "online check succeeded for entry with id: {}",
            rekor_bundle.payload.log_index
        );
        let image_data = source.get_artifact(&source_image_with_digest).await?;
        let cosign_bundle = match source.get_bundle(&source_image_with_digest).await {
            Ok(bundle) => bundle,
            Err(_) => {
                return Ok(Binary(image_data));
            }
        };
        let rekor_key = CosignVerificationKey::from_pem(
            self.keys.rekor_pub_key.as_bytes(),
            &SigningScheme::default(),
        )
        .map_err(|err| anyhow!("Failed to parse Rekor key {err}"))?;

        let signed_bundle = SignedArtifactBundle::new_verified(
            std::str::from_utf8(&cosign_bundle).context("bundle had invalid UTF-8")?,
            &rekor_key,
        )
        .map_err(|err| anyhow!("failed to produce signed artifact bundle {err}"))?;

        let entry = self
            .rekor_client
            .get_log_entry(signed_bundle.rekor_bundle.payload.log_index as u64)
            .await
            .map_err(|err| anyhow!("failed to get online entry {err}"))?;

        // Verify inclusion
        let inclusion_proof = entry
            .verification
            .inclusion_proof
            .context("online entry did contain inclusion proof")?;
        verify_inclusion_bundle(&signed_bundle.rekor_bundle.payload.body, &inclusion_proof)
            .map_err(|_| anyhow!("inclusion proof failed"))?;

        // Gossip entry to monitor
        let checkpoint = inclusion_proof
            .checkpoint
            .parse()
            .context("failed to parse checkpoint")?;

        for url in &self.monitors {
            send_checkpoint(url, &checkpoint).await.map_err(|err| {
                anyhow!("failed to get consistency confirmation from monitor {err:?}")
            })?;
        }

        self.cosign_client
            .verify_blob_with_bundle(image_data.as_slice(), &signed_bundle.rekor_bundle)
            .map_err(|err| anyhow!("failed to verify blob with bundle {err:?}"))?;

        Ok(BundledBinary {
            binary: image_data,
            bundle: cosign_bundle,
        })
    }
}

#[derive(Debug)]
pub struct InclusionVerifier {
    pub(crate) online_entry: LogEntry,
}

impl VerificationConstraint for InclusionVerifier {
    fn verify(&self, signature_layer: &SignatureLayer) -> sigstore::errors::Result<bool> {
        let Some(inclusion_proof) = self.online_entry.verification.inclusion_proof.as_ref() else {
            return Ok(false);
        };
        use sigstore::cosign::bundle::{Bundle, Payload};
        if let SignatureLayer {
            bundle:
                Some(Bundle {
                    payload: Payload { body, .. },
                    ..
                }),
            ..
        } = signature_layer
        {
            match verify_inclusion_bundle(body, inclusion_proof) {
                Ok(_) => Ok(true),
                Err(_) => Ok(false),
            }
        } else {
            Ok(false)
        }
    }
}

pub fn verify_inclusion_rekor_entry(
    body: &Body,
    inclusion_proof: &InclusionProof,
) -> Result<(), Bt2XError> {
    let mut body_serialized = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut body_serialized, CanonicalFormatter::new());
    body.serialize(&mut ser).unwrap();
    verify_inclusion_raw(&body_serialized, inclusion_proof)
}

pub fn verify_inclusion_bundle(
    body: &PayloadBody,
    inclusion_proof: &InclusionProof,
) -> Result<(), Bt2XError> {
    let mut body_serialized = Vec::new();
    let mut ser =
        serde_json::Serializer::with_formatter(&mut body_serialized, CanonicalFormatter::new());
    body.serialize(&mut ser).unwrap();
    verify_inclusion_raw(&body_serialized, inclusion_proof)
}

pub(crate) fn verify_inclusion_raw(
    body: &[u8],
    inclusion_proof: &InclusionProof,
) -> Result<(), Bt2XError> {
    let leaf_hash = Rfc6269Default::hash_leaf(body);
    let proof_hashes: Vec<Output<Rfc6269Default>> = inclusion_proof
        .hashes
        .iter()
        .map(|h| {
            hex::decode(h)
                .map_err(Bt2XError::HexDecodingError)
                .and_then(|h| {
                    <[u8; 32]>::try_from(h.as_slice()).map_err(|_| Bt2XError::InvalidHashLength)
                })
                .map(Output::<Rfc6269Default>::from)
        })
        .collect::<Result<Vec<_>, Bt2XError>>()?;

    let root_hash = hex::decode(&inclusion_proof.root_hash)
        .map_err(Bt2XError::HexDecodingError)
        .and_then(|h| <[u8; 32]>::try_from(h.as_slice()).map_err(|_| Bt2XError::InvalidHashLength))
        .map(Output::<Rfc6269Default>::from)?;

    Rfc6269Default::verify_inclusion(
        inclusion_proof.log_index as usize,
        &leaf_hash,
        inclusion_proof.tree_size as usize,
        &proof_hashes,
        &root_hash,
    )
    .map_err(Bt2XError::InclusionProofFailed)?;
    Ok(())
}

pub fn verify_consistency(
    old_size: usize,
    new_size: usize,
    proof: &ConsistencyProof,
    old_root: &[u8; 32],
    new_root: &[u8; 32],
) -> Result<(), Bt2XError> {
    let proof_hashes: Vec<_> = proof
        .hashes
        .iter()
        .map(|s| {
            hex::decode(s)
                .map_err(Bt2XError::HexDecodingError)
                .and_then(|v| {
                    <[u8; 32]>::try_from(v.as_slice()).map_err(|_| Bt2XError::InvalidHashLength)
                })
                .map(Output::<Rfc6269Default>::from)
        })
        .collect::<Result<Vec<_>, Bt2XError>>()?;

    Rfc6269Default::verify_consistency(
        old_size,
        new_size,
        &proof_hashes,
        old_root.into(),
        new_root.into(),
    )
    .map_err(Bt2XError::ConsistencyProofFailed)
}

#[cfg(feature = "bt")]
pub mod constraints {
    use sigstore::cosign::verification_constraint::VerificationConstraint;
    use sigstore::cosign::SignatureLayer;

    #[derive(Debug)]
    pub struct KeylessSigningEnforcer {}

    impl VerificationConstraint for KeylessSigningEnforcer {
        fn verify(&self, signature_layer: &SignatureLayer) -> sigstore::errors::Result<bool> {
            Ok(signature_layer.certificate_signature.is_some())
        }
    }
}

#[cfg(test)]
mod test {
    use crate::verifier::bt::verify_inclusion_rekor_entry;

    #[tokio::test]
    async fn test_verify_inclusion() {
        let rekor_config = sigstore::rekor::apis::configuration::Configuration::default();
        let entry =
            sigstore::rekor::apis::entries_api::get_log_entry_by_index(&rekor_config, 16056995)
                .await
                .expect("could not fetch entry");

        assert!(verify_inclusion_rekor_entry(
            &entry.body,
            &entry.verification.inclusion_proof.unwrap()
        )
        .is_ok());
    }

    #[tokio::test]
    async fn test_verify_inclusion_fail() {
        let rekor_config = sigstore::rekor::apis::configuration::Configuration::default();
        let mut entry =
            sigstore::rekor::apis::entries_api::get_log_entry_by_index(&rekor_config, 16056995)
                .await
                .expect("could not fetch entry");
        entry
            .verification
            .inclusion_proof
            .as_mut()
            .unwrap()
            .log_index += 1;
        assert!(verify_inclusion_rekor_entry(
            &entry.body,
            &entry.verification.inclusion_proof.unwrap()
        )
        .is_err());
    }
}
