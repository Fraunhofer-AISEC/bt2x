use digest::Output;
use sha2::{Digest, Sha256};

#[repr(u8)]
pub enum Rfc6269HashPrefix {
    RFC6962LeafHashPrefix = 0,
    RFC6962NodeHashPrefix = 1,
}

pub trait Rfc6269HasherTrait<O> {
    fn empty_root() -> O;
    fn hash_leaf(leaf: &[u8]) -> O;
    fn hash_children(left: &[u8], right: &[u8]) -> O;
}

impl<T> Rfc6269HasherTrait<Output<T>> for T
where
    T: Digest,
{
    fn empty_root() -> Output<T> {
        T::new().finalize()
    }
    fn hash_leaf(leaf: &[u8]) -> Output<T> {
        T::new()
            .chain_update([Rfc6269HashPrefix::RFC6962LeafHashPrefix as u8])
            .chain_update(leaf)
            .finalize()
    }
    fn hash_children(left: &[u8], right: &[u8]) -> Output<T> {
        T::new()
            .chain_update([Rfc6269HashPrefix::RFC6962NodeHashPrefix as u8])
            .chain_update(left)
            .chain_update(right)
            .finalize()
    }
}

pub type Rfc6269Default = Sha256;

#[cfg(test)]
mod test_rfc6962 {
    use crate::merkle::rfc6962::Rfc6269Default;
    use crate::merkle::rfc6962::Rfc6269HasherTrait;
    use hex_literal::hex;

    #[derive(Debug, PartialEq)]
    struct TestCase {
        pub desc: String,
        pub got: [u8; 32],
        pub want: [u8; 32],
    }

    #[test]
    fn test_hasher() {
        let leaf_hash = Rfc6269Default::hash_leaf(b"L123456");
        let empty_leaf_hash = Rfc6269Default::hash_leaf(b"");
        let test_cases: Vec<_> = [
            TestCase {
                desc: "RFC6962 Empty".to_string(),
                want: hex!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
                got: Rfc6269Default::empty_root().into(),
            },
            TestCase {
                desc: "RFC6962 Empty Leaf".to_string(),
                want: hex!("6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"),
                got: empty_leaf_hash.into(),
            },
            TestCase {
                desc: "RFC6962 Leaf".to_string(),
                want: hex!("395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56"),
                got: leaf_hash.into(),
            },
            TestCase {
                desc: "RFC6962 Node".to_string(),
                want: hex!("aa217fe888e47007fa15edab33c2b492a722cb106c64667fc2b044444de66bbb"),
                got: Rfc6269Default::hash_children(b"N123", b"N456").into(),
            },
        ]
        .into_iter()
        .filter(|tc| tc.got != tc.want)
        .collect();
        assert_eq!(test_cases.len(), 0, "failed tests: {test_cases:?}")
    }

    #[test]
    fn test_collisions() {
        let l1 = b"Hello".to_vec();
        let l2 = b"World".to_vec();
        let hash1 = Rfc6269Default::hash_leaf(&l1);
        let hash2 = Rfc6269Default::hash_leaf(&l2);
        assert_ne!(hash1, hash2, "got identical hashes for different leafs");

        let sub_hash1 = Rfc6269Default::hash_children(&l1, &l2);
        let sub_hash2 = Rfc6269Default::hash_children(&l2, &l1);
        assert_ne!(sub_hash1, sub_hash2, "got same hash for different order");

        let forged_hash = Rfc6269Default::hash_leaf(&[l1, l2].concat());
        assert_ne!(
            sub_hash1, forged_hash,
            "hasher is not second-preimage resistant"
        );
    }
}
