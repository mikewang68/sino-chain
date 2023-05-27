use std::collections::{BTreeSet, HashMap};

use primitive_types::H256;
use rlp::Rlp;
use sha3::{Digest, Keccak256};

#[cfg(test)]
use serde::{Deserialize, Serialize};

#[cfg(test)]
pub(crate) mod tests;

use crate::debug::no_childs;
use crate::diff;
use crate::gc::{DbCounter, ReachableHashes};
use crate::merkle::MerkleNode;

#[cfg_attr(test, derive(Serialize, Deserialize))]
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct VerifiedPatch {
    pub(crate) patch_dependencies: Option<BTreeSet<H256>>,
    pub(crate) sorted_changes: Vec<(H256, bool, Vec<u8>)>,
    pub(crate) target_root: H256,
}

#[derive(Debug)]
pub enum VerificationError {
    MissExpectedRoot(H256),
    MissDependencyDB(H256),
    HashMismatch(H256, H256),
}

impl std::error::Error for VerificationError {
    fn description(&self) -> &str {
        "patch consistency verification error"
    }
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self, f)
    }
}

pub fn verify_hash(value: &[u8], hash: H256) -> crate::Result<()> {
    let actual_hash = H256::from_slice(Keccak256::digest(value).as_slice());
    if hash != actual_hash {
        return Err(VerificationError::HashMismatch(hash, actual_hash))?;
    }
    Ok(())
}

fn verify_node(
    hash: H256,
    map: &HashMap<H256, Vec<u8>>,
) -> crate::Result<Option<(Vec<u8>, MerkleNode<'_>)>> {
    let value = match map.get(&hash) {
        Some(value) => value,
        None => return Ok(None),
    };

    verify_hash(value, hash)?;

    let node = MerkleNode::decode(&Rlp::new(value))?;
    Ok(Some((value.clone(), node)))
}

/// This is function to verify and sort patch before application
///
/// `collect_dependencies` - this is made optional, as collected `patch_dependencies` can be
/// manyfold greater in size then the actual `sorted_changes`, and true is only needed for
/// tests
pub fn verify<D, F>(
    database: &D,
    expected_root: H256,
    unsorted: Vec<diff::Change>,
    child_extractor: F,
    collect_dependencies: bool,
) -> crate::Result<VerifiedPatch>
where
    D: DbCounter,
    F: FnMut(&[u8]) -> Vec<H256> + Clone,
{
    let mut map: HashMap<H256, Vec<u8>> = HashMap::new();
    for change in unsorted.into_iter() {
        match change {
            diff::Change::Insert(key, value) => {
                map.insert(key, value.into());
            }
            diff::Change::Removal(..) => {}
        };
    }
    let (value, node) = verify_node(expected_root, &map)?
        .ok_or(VerificationError::MissExpectedRoot(expected_root))?;

    let mut patch_dependencies: BTreeSet<H256> = BTreeSet::new();
    let mut sorted_changes: Vec<(H256, bool, Vec<u8>)> = vec![(expected_root, true, value)];

    let (direct_childs, indirect_childs) =
        ReachableHashes::collect(&node, child_extractor.clone()).childs();

    let mut current_subtrees: Vec<_> = direct_childs
        .into_iter()
        .map(|k| (k, true))
        .chain(indirect_childs.into_iter().map(|k| (k, false)))
        .collect();

    while !current_subtrees.is_empty() {
        let mut next_childs = vec![];
        for (hash, is_direct) in current_subtrees.drain(..) {
            match verify_node(hash, &map)? {
                Some((value, node)) => {
                    sorted_changes.push((hash, is_direct, value));
                    let (direct_childs, indirect_childs) = if is_direct {
                        ReachableHashes::collect(&node, child_extractor.clone()).childs()
                    } else {
                        // prevent more than one layer of indirection
                        let childs = ReachableHashes::collect(&node, no_childs).childs();
                        assert!(
                            childs.1.is_empty(),
                            "There should be no subtrie with 'no_childs' extractor"
                        );
                        // All direct childs for indirect childs should be handled as indirect.
                        (vec![], childs.0)
                    };
                    // continue verification downward, if current node is inserted as part of
                    // patch
                    next_childs.extend(
                        direct_childs
                            .into_iter()
                            .map(|k| (k, true))
                            .chain(indirect_childs.into_iter().map(|k| (k, false))),
                    );
                }
                None => {
                    if database.node_exist(hash) {
                        if collect_dependencies {
                            patch_dependencies.insert(hash);
                        }
                        // terminate verification downward, as subtree root that patch depends
                        // onto is present at moment of verification
                    } else {
                        return Err(VerificationError::MissDependencyDB(hash))?;
                    }
                }
            }
        }

        current_subtrees.append(&mut next_childs);
    }

    Ok(VerifiedPatch {
        patch_dependencies: collect_dependencies.then_some(patch_dependencies),
        sorted_changes,
        target_root: expected_root,
    })
}
