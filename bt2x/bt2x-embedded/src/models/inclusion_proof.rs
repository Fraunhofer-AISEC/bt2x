/*
 * Rekor
 *
 * Rekor is a cryptographically secure, immutable transparency log for signed software releases.
 *
 * The version of the OpenAPI document: 1.0.0
 * 
 * Generated by: https://openapi-generator.tech
 */


#[cfg(feature = "no_std")]
use alloc::vec::Vec;
#[cfg(feature = "no_std")]
use alloc::string::String;


use serde_with::serde_as;
use serde_with::hex::Hex;

#[serde_as]
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InclusionProof {
    /// The index of the entry in the transparency log
    #[serde(rename = "logIndex")]
    pub log_index: i32,
    /// The hash value stored at the root of the merkle tree at the time the proof was generated
    #[serde_as(as = "Hex")]
    pub root_hash: [u8; 32],
    /// The size of the merkle tree at the time the inclusion proof was generated
    #[serde(rename = "treeSize")]
    pub tree_size: u64,
    /// A list of hashes required to compute the inclusion proof, sorted in order from leaf to root
    #[serde_as(as = "Vec<Hex>")]
    pub hashes: Vec<[u8; 32]>,
    /// The checkpoint (signed tree head) that the inclusion proof is based on
    #[serde(rename = "checkpoint")]
    pub checkpoint: String,
}

impl InclusionProof {
    pub fn new(log_index: i32, root_hash: [u8; 32], tree_size: u64, hashes: Vec<[u8; 32]>, checkpoint: String) -> InclusionProof {
        InclusionProof {
            log_index,
            root_hash,
            tree_size,
            hashes,
            checkpoint,
        }
    }
}


