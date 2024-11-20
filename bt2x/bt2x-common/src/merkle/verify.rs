use crate::merkle::rfc6962::Rfc6269HasherTrait;
use crate::merkle::verify::ProofError::*;
use digest::{Digest, Output};
use std::cmp::Ordering;
use std::fmt::Debug;

#[derive(Debug)]
pub enum ProofError {
    MismatchedRoot { expected: String, got: String },
    IndexGtTreeSize,
    UnexpectedNonEmptyProof,
    UnexpectedEmptyProof,
    NewTreeSmaller { new: usize, old: usize },
    WrongProofSize { got: usize, want: usize },
}

pub trait MerkleProofVerifier<O>: Rfc6269HasherTrait<O>
where
    O: Eq + AsRef<[u8]> + Clone + Debug,
{
    #[allow(clippy::result_unit_err)]
    fn verify_match(a: &O, b: &O) -> Result<(), ()> {
        (a == b).then_some(()).ok_or(())
    }

    fn verify_inclusion(
        index: usize,
        leaf_hash: &O,
        tree_size: usize,
        proof_hashes: &[O],
        root_hash: &O,
    ) -> Result<(), ProofError> {
        if index >= tree_size {
            return Err(IndexGtTreeSize);
        }
        Self::root_from_inclusion_proof(index, leaf_hash, tree_size, proof_hashes).and_then(
            |calc_root| {
                Self::verify_match(calc_root.as_ref(), root_hash).map_err(|_| MismatchedRoot {
                    got: hex::encode(root_hash),
                    expected: hex::encode(*calc_root),
                })
            },
        )
    }

    fn root_from_inclusion_proof(
        index: usize,
        leaf_hash: &O,
        tree_size: usize,
        proof_hashes: &[O],
    ) -> Result<Box<O>, ProofError> {
        if index >= tree_size {
            return Err(IndexGtTreeSize);
        }
        let (inner, border) = Self::decomp_inclusion_proof(index, tree_size);
        match (proof_hashes.len(), inner + border) {
            (got, want) if got != want => {
                return Err(WrongProofSize {
                    got: proof_hashes.len(),
                    want: inner + border,
                })
            }
            _ => {}
        }

        let res_left = Self::chain_inner(leaf_hash, &proof_hashes[..inner], index);
        let res = Self::chain_border_right(&res_left, &proof_hashes[inner..]);
        Ok(Box::new(res))
    }

    fn verify_consistency(
        old_size: usize,
        new_size: usize,
        proof_hashes: &[O],
        old_root: &O,
        new_root: &O,
    ) -> Result<(), ProofError> {
        match Ord::cmp(&old_size, &new_size) {
            Ordering::Greater => {
                return Err(NewTreeSmaller {
                    new: new_size,
                    old: old_size,
                })
            }
            Ordering::Equal if Self::verify_match(new_root, old_root).is_err() => {
                return Err(MismatchedRoot {
                    got: hex::encode(new_root),
                    expected: hex::encode(old_root),
                })
            }
            Ordering::Equal if old_size == new_size && proof_hashes.is_empty() => {
                return Ok(());
            }
            _ => {}
        };
        match (new_size == old_size, proof_hashes.is_empty()) {
            (true, false) => return Err(UnexpectedNonEmptyProof),
            (false, true) => return Err(UnexpectedEmptyProof),
            (true, true) => {
                unreachable!("this should be unreachable");
            }
            _ => {}
        }
        let (mut inner, border) = Self::decomp_inclusion_proof(old_size - 1, new_size);
        let shift = old_size.trailing_zeros() as usize;
        inner -= shift;

        let mut seed = &proof_hashes[0];
        let mut start = 1;
        if old_size == 1 << shift {
            seed = old_root;
            start = 0;
        }
        let got = proof_hashes.len();
        let want = start + inner + border;
        if got != want {
            return Err(WrongProofSize { got, want });
        }
        let proof = &proof_hashes[start..];
        let mask = (old_size - 1) >> shift;
        let hash1 = Self::chain_inner_right(seed, &proof[..inner], mask);
        let hash1 = Self::chain_border_right(&hash1, &proof[inner..]);
        Self::verify_match(&hash1, old_root).map_err(|_| MismatchedRoot {
            got: hex::encode(old_root),
            expected: hex::encode(hash1),
        })?;
        let hash2 = Self::chain_inner(seed, &proof[..inner], mask);
        let hash2 = Self::chain_border_right(&hash2, &proof[inner..]);
        Self::verify_match(&hash2, new_root).map_err(|_| MismatchedRoot {
            got: hex::encode(new_root),
            expected: hex::encode(old_root),
        })?;
        Ok(())
    }
    fn chain_inner(seed: &O, proof_hashes: &[O], index: usize) -> O {
        proof_hashes
            .iter()
            .enumerate()
            .fold(seed.clone(), |seed, (i, h)| {
                if (index >> i) & 1 == 0 {
                    Self::hash_children(seed.as_ref(), h.as_ref())
                } else {
                    Self::hash_children(h.as_ref(), seed.as_ref())
                }
            })
    }

    fn chain_inner_right(seed: &O, proof_hashes: &[O], index: usize) -> O {
        proof_hashes
            .iter()
            .enumerate()
            .fold(seed.clone(), |seed, (i, h)| {
                if (index >> i) & 1 == 1 {
                    Self::hash_children(h.as_ref(), seed.as_ref())
                } else {
                    seed
                }
            })
    }

    fn chain_border_right(seed: &O, proof_hashes: &[O]) -> O {
        proof_hashes.iter().fold(seed.clone(), |seed, h| {
            Self::hash_children(h.as_ref(), seed.as_ref())
        })
    }

    fn decomp_inclusion_proof(index: usize, tree_size: usize) -> (usize, usize) {
        let inner: usize = Self::inner_proof_size(index, tree_size);
        let border = (index >> inner).count_ones() as usize;
        (inner, border)
    }

    fn inner_proof_size(index: usize, tree_size: usize) -> usize {
        u64::BITS as usize - ((index ^ (tree_size - 1)).leading_zeros() as usize)
    }
}

impl<T> MerkleProofVerifier<Output<T>> for T where T: Digest {}
