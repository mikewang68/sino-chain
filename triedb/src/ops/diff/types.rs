use crate::merkle::{Branch, Leaf};

/// Same MerkleNode but without Extension (because they internally used only for branches)
/// Currently used for diff, later need refactor original MerkleNode to
///
/// enum MerkleNode {
///     Extension(Extension), // Extension<'a> = NibbleSlice | MerkleValue<Branch>
///     DataNode(DataMerkleNode) // DataMerkleNode will beinternally the same as this structure,
///                              // but maybe better naming is needed
/// }
pub enum DataMerkleNode<'a> {
    Leaf(Leaf<'a>),
    Branch(Branch<'a>),
}

// #[derive(Clone, Debug, PartialEq, Eq)]
// #[allow(clippy::large_enum_variant)]
// pub enum RegularMerkleNode<'a>{

// }
