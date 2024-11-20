use crate::merkle::rfc6962::{Rfc6269Default, Rfc6269HasherTrait};
use digest::Output;

pub fn calc_tree(entries: &[impl AsRef<[u8]>]) -> Output<Rfc6269Default> {
    if entries.is_empty() {
        return Rfc6269Default::empty_root();
    }
    let leaf_hashes: Vec<_> = entries
        .iter()
        .map(|entry| Rfc6269Default::hash_leaf(entry.as_ref()))
        .collect();
    tree_rec(&leaf_hashes)
}

fn tree_rec(children: &[Output<Rfc6269Default>]) -> Output<Rfc6269Default> {
    match children {
        [leaf] => *leaf,
        [left, right] => Rfc6269Default::hash_children(left.as_slice(), right.as_slice()),
        many => {
            let (left, right) = many.split_at((many.len() - 1) / 2 + 1);
            tree_rec(&[tree_rec(left), tree_rec(right)])
        }
    }
}

#[cfg(test)]
mod test_tree {
    use crate::merkle::rfc6962::{Rfc6269Default, Rfc6269HasherTrait};
    use crate::merkle::tree::calc_tree;

    #[test]
    pub fn test_0() {
        let input: Vec<&[u8]> = vec![];
        let hash = calc_tree(&input);
        assert_eq!(hash, Rfc6269Default::empty_root())
    }

    #[test]
    pub fn test_1() {
        let input = [[0_u8]];
        let hash = calc_tree(&input);
        assert_eq!(hash, Rfc6269Default::hash_leaf([0].as_slice()))
    }

    #[test]
    pub fn test_2() {
        let input = vec![[0], [1]];
        let hash = calc_tree(&input);
        assert_eq!(
            hash,
            Rfc6269Default::hash_children(
                Rfc6269Default::hash_leaf([0].as_slice()).as_slice(),
                Rfc6269Default::hash_leaf([1].as_slice()).as_slice(),
            )
        )
    }

    #[test]
    pub fn test_3() {
        let input = vec![[0], [1], [2]];
        let hash = calc_tree(&input);
        assert_eq!(
            hash,
            Rfc6269Default::hash_children(
                Rfc6269Default::hash_children(
                    Rfc6269Default::hash_leaf([0].as_slice()).as_slice(),
                    Rfc6269Default::hash_leaf([1].as_slice()).as_slice(),
                )
                .as_slice(),
                Rfc6269Default::hash_leaf([2].as_slice()).as_slice(),
            )
        )
    }

    #[test]
    pub fn test_4() {
        let input = vec![[0], [1], [2], [3]];
        let hash = calc_tree(&input);
        assert_eq!(
            hash,
            Rfc6269Default::hash_children(
                Rfc6269Default::hash_children(
                    Rfc6269Default::hash_leaf([0].as_slice()).as_slice(),
                    Rfc6269Default::hash_leaf([1].as_slice()).as_slice(),
                )
                .as_slice(),
                Rfc6269Default::hash_children(
                    Rfc6269Default::hash_leaf([2].as_slice()).as_slice(),
                    Rfc6269Default::hash_leaf([3].as_slice()).as_slice(),
                )
                .as_slice(),
            )
        )
    }
}
