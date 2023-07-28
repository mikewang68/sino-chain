use {
    crate::{
        cluster_info::MAX_SNAPSHOT_HASHES,
        contact_info::ContactInfo,
        deprecated,
        duplicate_shred::{DuplicateShred, DuplicateShredIndex, MAX_DUPLICATE_SHREDS},
        epoch_slots::EpochSlots,
    },
    bincode::{serialize, serialized_size},
    rand::{CryptoRng, Rng},
    serde::de::{Deserialize, Deserializer},
    runtime::vote_parser,
    sdk::{
        clock::Slot,
        hash::Hash,
        pubkey::{self, Pubkey},
        sanitize::{Sanitize, SanitizeError},
        signature::{Keypair, Signable, Signature, Signer},
        timing::timestamp,
        transaction::Transaction,
    },
    std::{
        borrow::{Borrow, Cow},
        cmp::Ordering,
        collections::{hash_map::Entry, BTreeSet, HashMap},
        fmt,
    },
};

pub const MAX_WALLCLOCK: u64 = 1_000_000_000_000_000;
pub const MAX_SLOT: u64 = 1_000_000_000_000_000;

pub type VoteIndex = u8;
// TODO: Remove this in favor of vote_state::MAX_LOCKOUT_HISTORY once
// the fleet is updated to the new ClusterInfo::push_vote code.
pub const MAX_VOTES: VoteIndex = 32;

pub type EpochSlotsIndex = u8;
pub const MAX_EPOCH_SLOTS: EpochSlotsIndex = 255;

/// CrdsValue that is replicated across the cluster
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample)]
pub struct CrdsValue {
    pub signature: Signature,
    pub data: CrdsData,
}

impl Sanitize for CrdsValue {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        self.signature.sanitize()?;
        self.data.sanitize()
    }
}

impl Signable for CrdsValue {
    fn pubkey(&self) -> Pubkey {
        self.pubkey()
    }

    fn signable_data(&self) -> Cow<[u8]> {
        Cow::Owned(serialize(&self.data).expect("failed to serialize CrdsData"))
    }

    fn get_signature(&self) -> Signature {
        self.signature
    }

    fn set_signature(&mut self, signature: Signature) {
        self.signature = signature
    }

    fn verify(&self) -> bool {
        self.get_signature()
            .verify(self.pubkey().as_ref(), self.signable_data().borrow())
    }
}

/// CrdsData that defines the different types of items CrdsValues can hold
/// * Merge Strategy - Latest wallclock is picked
/// * LowestSlot index is deprecated
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample, AbiEnumVisitor)]
pub enum CrdsData {
    ContactInfo(ContactInfo),
    Vote(VoteIndex, Vote),
    LowestSlot(/*DEPRECATED:*/ u8, LowestSlot),
    SnapshotHashes(SnapshotHashes),
    AccountsHashes(SnapshotHashes),
    EpochSlots(EpochSlotsIndex, EpochSlots),
    LegacyVersion(LegacyVersion),
    Version(Version),
    NodeInstance(NodeInstance),
    DuplicateShred(DuplicateShredIndex, DuplicateShred),
    IncrementalSnapshotHashes(IncrementalSnapshotHashes),
}

impl Sanitize for CrdsData {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        match self {
            CrdsData::ContactInfo(val) => val.sanitize(),
            CrdsData::Vote(ix, val) => {
                if *ix >= MAX_VOTES {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                val.sanitize()
            }
            CrdsData::LowestSlot(ix, val) => {
                if *ix as usize >= 1 {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                val.sanitize()
            }
            CrdsData::SnapshotHashes(val) => val.sanitize(),
            CrdsData::AccountsHashes(val) => val.sanitize(),
            CrdsData::EpochSlots(ix, val) => {
                if *ix as usize >= MAX_EPOCH_SLOTS as usize {
                    return Err(SanitizeError::ValueOutOfBounds);
                }
                val.sanitize()
            }
            CrdsData::LegacyVersion(version) => version.sanitize(),
            CrdsData::Version(version) => version.sanitize(),
            CrdsData::NodeInstance(node) => node.sanitize(),
            CrdsData::DuplicateShred(ix, shred) => {
                if *ix >= MAX_DUPLICATE_SHREDS {
                    Err(SanitizeError::ValueOutOfBounds)
                } else {
                    shred.sanitize()
                }
            }
            CrdsData::IncrementalSnapshotHashes(val) => val.sanitize(),
        }
    }
}

/// Random timestamp for tests and benchmarks.
pub(crate) fn new_rand_timestamp<R: Rng>(rng: &mut R) -> u64 {
    const DELAY: u64 = 10 * 60 * 1000; // 10 minutes
    timestamp() - DELAY + rng.gen_range(0, 2 * DELAY)
}

impl CrdsData {
    /// New random CrdsData for tests and benchmarks.
    fn new_rand<R: Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> CrdsData {
        let kind = rng.gen_range(0, 7);
        // TODO: Implement other kinds of CrdsData here.
        // TODO: Assign ranges to each arm proportional to their frequency in
        // the mainnet crds table.
        match kind {
            0 => CrdsData::ContactInfo(ContactInfo::new_rand(rng, pubkey)),
            1 => CrdsData::LowestSlot(rng.gen(), LowestSlot::new_rand(rng, pubkey)),
            2 => CrdsData::SnapshotHashes(SnapshotHashes::new_rand(rng, pubkey)),
            3 => CrdsData::AccountsHashes(SnapshotHashes::new_rand(rng, pubkey)),
            4 => CrdsData::Version(Version::new_rand(rng, pubkey)),
            5 => CrdsData::Vote(rng.gen_range(0, MAX_VOTES), Vote::new_rand(rng, pubkey)),
            _ => CrdsData::EpochSlots(
                rng.gen_range(0, MAX_EPOCH_SLOTS),
                EpochSlots::new_rand(rng, pubkey),
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample)]
pub struct SnapshotHashes {
    pub from: Pubkey,
    pub hashes: Vec<(Slot, Hash)>,
    pub wallclock: u64,
}

impl Sanitize for SnapshotHashes {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        for (slot, _) in &self.hashes {
            if *slot >= MAX_SLOT {
                return Err(SanitizeError::ValueOutOfBounds);
            }
        }
        self.from.sanitize()
    }
}

impl SnapshotHashes {
    pub fn new(from: Pubkey, hashes: Vec<(Slot, Hash)>) -> Self {
        Self {
            from,
            hashes,
            wallclock: timestamp(),
        }
    }

    /// New random SnapshotHashes for tests and benchmarks.
    pub(crate) fn new_rand<R: Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> Self {
        let num_hashes = rng.gen_range(0, MAX_SNAPSHOT_HASHES) + 1;
        let hashes = std::iter::repeat_with(|| {
            let slot = 47825632 + rng.gen_range(0, 512);
            let hash = sdk::hash::new_rand(rng);
            (slot, hash)
        })
        .take(num_hashes)
        .collect();
        Self {
            from: pubkey.unwrap_or_else(pubkey::new_rand),
            hashes,
            wallclock: new_rand_timestamp(rng),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample)]
pub struct IncrementalSnapshotHashes {
    pub from: Pubkey,
    pub base: (Slot, Hash),
    pub hashes: Vec<(Slot, Hash)>,
    pub wallclock: u64,
}

impl Sanitize for IncrementalSnapshotHashes {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        if self.base.0 >= MAX_SLOT {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        for (slot, _) in &self.hashes {
            if *slot >= MAX_SLOT {
                return Err(SanitizeError::ValueOutOfBounds);
            }
            if self.base.0 >= *slot {
                return Err(SanitizeError::InvalidValue);
            }
        }
        self.from.sanitize()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample)]
pub struct LowestSlot {
    pub from: Pubkey,
    root: Slot, //deprecated
    pub lowest: Slot,
    slots: BTreeSet<Slot>,                        //deprecated
    stash: Vec<deprecated::EpochIncompleteSlots>, //deprecated
    pub wallclock: u64,
}

impl LowestSlot {
    pub fn new(from: Pubkey, lowest: Slot, wallclock: u64) -> Self {
        Self {
            from,
            root: 0,
            lowest,
            slots: BTreeSet::new(),
            stash: vec![],
            wallclock,
        }
    }

    /// New random LowestSlot for tests and benchmarks.
    fn new_rand<R: Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> Self {
        Self {
            from: pubkey.unwrap_or_else(pubkey::new_rand),
            root: rng.gen(),
            lowest: rng.gen(),
            slots: BTreeSet::default(),
            stash: Vec::default(),
            wallclock: new_rand_timestamp(rng),
        }
    }
}

impl Sanitize for LowestSlot {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        if self.lowest >= MAX_SLOT {
            return Err(SanitizeError::ValueOutOfBounds);
        }
        if self.root != 0 {
            return Err(SanitizeError::InvalidValue);
        }
        if !self.slots.is_empty() {
            return Err(SanitizeError::InvalidValue);
        }
        if !self.stash.is_empty() {
            return Err(SanitizeError::InvalidValue);
        }
        self.from.sanitize()
    }
}

#[derive(Clone, Debug, PartialEq, AbiExample, Serialize)]
pub struct Vote {
    pub(crate) from: Pubkey,
    transaction: Transaction,
    pub(crate) wallclock: u64,
    #[serde(skip_serializing)]
    slot: Option<Slot>,
}

impl Sanitize for Vote {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        self.from.sanitize()?;
        self.transaction.sanitize()
    }
}

impl Vote {
    // Returns None if cannot parse transaction into a vote.
    pub fn new(from: Pubkey, transaction: Transaction, wallclock: u64) -> Option<Self> {
        vote_parser::parse_vote_transaction(&transaction).map(|(_, vote, _)| Self {
            from,
            transaction,
            wallclock,
            slot: vote.slots.last().copied(),
        })
    }

    /// New random Vote for tests and benchmarks.
    fn new_rand<R: Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> Self {
        Self {
            from: pubkey.unwrap_or_else(pubkey::new_rand),
            transaction: Transaction::default(),
            wallclock: new_rand_timestamp(rng),
            slot: None,
        }
    }

    pub(crate) fn transaction(&self) -> &Transaction {
        &self.transaction
    }

    pub(crate) fn slot(&self) -> Option<Slot> {
        self.slot
    }
}

impl<'de> Deserialize<'de> for Vote {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Vote {
            from: Pubkey,
            transaction: Transaction,
            wallclock: u64,
        }
        let vote = Vote::deserialize(deserializer)?;
        vote.transaction
            .sanitize()
            .map_err(serde::de::Error::custom)?;
        Self::new(vote.from, vote.transaction, vote.wallclock)
            .ok_or_else(|| serde::de::Error::custom("invalid vote tx"))
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample)]
pub struct LegacyVersion {
    pub from: Pubkey,
    pub wallclock: u64,
    pub version: version::LegacyVersion,
}

impl Sanitize for LegacyVersion {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        self.from.sanitize()?;
        self.version.sanitize()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, AbiExample)]
pub struct Version {
    pub from: Pubkey,
    pub wallclock: u64,
    pub version: version::Version,
}

impl Sanitize for Version {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        self.from.sanitize()?;
        self.version.sanitize()
    }
}

impl Version {
    pub fn new(from: Pubkey) -> Self {
        Self {
            from,
            wallclock: timestamp(),
            version: version::Version::default(),
        }
    }

    /// New random Version for tests and benchmarks.
    fn new_rand<R: Rng>(rng: &mut R, pubkey: Option<Pubkey>) -> Self {
        Self {
            from: pubkey.unwrap_or_else(pubkey::new_rand),
            wallclock: new_rand_timestamp(rng),
            version: version::Version {
                major: rng.gen(),
                minor: rng.gen(),
                patch: rng.gen(),
                commit: Some(rng.gen()),
                feature_set: rng.gen(),
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq, AbiExample, Deserialize, Serialize)]
pub struct NodeInstance {
    from: Pubkey,
    wallclock: u64,
    timestamp: u64, // Timestamp when the instance was created.
    token: u64,     // Randomly generated value at node instantiation.
}

impl NodeInstance {
    pub fn new<R>(rng: &mut R, from: Pubkey, now: u64) -> Self
    where
        R: Rng + CryptoRng,
    {
        Self {
            from,
            wallclock: now,
            timestamp: now,
            token: rng.gen(),
        }
    }

    // Clones the value with an updated wallclock.
    pub(crate) fn with_wallclock(&self, wallclock: u64) -> Self {
        Self { wallclock, ..*self }
    }

    // Returns true if the crds-value is a duplicate instance
    // of this node, with a more recent timestamp.
    pub(crate) fn check_duplicate(&self, other: &CrdsValue) -> bool {
        match &other.data {
            CrdsData::NodeInstance(other) => {
                self.token != other.token
                    && self.timestamp <= other.timestamp
                    && self.from == other.from
            }
            _ => false,
        }
    }

    // Returns None if tokens are the same or other is not a node-instance from
    // the same owner. Otherwise returns true if self has more recent timestamp
    // than other, and so overrides it.
    pub(crate) fn overrides(&self, other: &CrdsValue) -> Option<bool> {
        let other = match &other.data {
            CrdsData::NodeInstance(other) => other,
            _ => return None,
        };
        if self.token == other.token || self.from != other.from {
            return None;
        }
        match self.timestamp.cmp(&other.timestamp) {
            Ordering::Less => Some(false),
            Ordering::Greater => Some(true),
            // Ties should be broken in a deterministic way across the cluster,
            // so that nodes propagate the same value through gossip.
            Ordering::Equal => Some(other.token < self.token),
        }
    }
}

impl Sanitize for NodeInstance {
    fn sanitize(&self) -> Result<(), SanitizeError> {
        sanitize_wallclock(self.wallclock)?;
        self.from.sanitize()
    }
}

/// Type of the replicated value
/// These are labels for values in a record that is associated with `Pubkey`
#[derive(PartialEq, Hash, Eq, Clone, Debug)]
pub enum CrdsValueLabel {
    ContactInfo(Pubkey),
    Vote(VoteIndex, Pubkey),
    LowestSlot(Pubkey),
    SnapshotHashes(Pubkey),
    EpochSlots(EpochSlotsIndex, Pubkey),
    AccountsHashes(Pubkey),
    LegacyVersion(Pubkey),
    Version(Pubkey),
    NodeInstance(Pubkey),
    DuplicateShred(DuplicateShredIndex, Pubkey),
    IncrementalSnapshotHashes(Pubkey),
}

impl fmt::Display for CrdsValueLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CrdsValueLabel::ContactInfo(_) => write!(f, "ContactInfo({})", self.pubkey()),
            CrdsValueLabel::Vote(ix, _) => write!(f, "Vote({}, {})", ix, self.pubkey()),
            CrdsValueLabel::LowestSlot(_) => write!(f, "LowestSlot({})", self.pubkey()),
            CrdsValueLabel::SnapshotHashes(_) => write!(f, "SnapshotHashes({})", self.pubkey()),
            CrdsValueLabel::EpochSlots(ix, _) => write!(f, "EpochSlots({}, {})", ix, self.pubkey()),
            CrdsValueLabel::AccountsHashes(_) => write!(f, "AccountsHashes({})", self.pubkey()),
            CrdsValueLabel::LegacyVersion(_) => write!(f, "LegacyVersion({})", self.pubkey()),
            CrdsValueLabel::Version(_) => write!(f, "Version({})", self.pubkey()),
            CrdsValueLabel::NodeInstance(pk) => write!(f, "NodeInstance({})", pk),
            CrdsValueLabel::DuplicateShred(ix, pk) => write!(f, "DuplicateShred({}, {})", ix, pk),
            CrdsValueLabel::IncrementalSnapshotHashes(_) => {
                write!(f, "IncrementalSnapshotHashes({})", self.pubkey())
            }
        }
    }
}

impl CrdsValueLabel {
    pub fn pubkey(&self) -> Pubkey {
        match self {
            CrdsValueLabel::ContactInfo(p) => *p,
            CrdsValueLabel::Vote(_, p) => *p,
            CrdsValueLabel::LowestSlot(p) => *p,
            CrdsValueLabel::SnapshotHashes(p) => *p,
            CrdsValueLabel::EpochSlots(_, p) => *p,
            CrdsValueLabel::AccountsHashes(p) => *p,
            CrdsValueLabel::LegacyVersion(p) => *p,
            CrdsValueLabel::Version(p) => *p,
            CrdsValueLabel::NodeInstance(p) => *p,
            CrdsValueLabel::DuplicateShred(_, p) => *p,
            CrdsValueLabel::IncrementalSnapshotHashes(p) => *p,
        }
    }
}

impl CrdsValue {
    pub fn new_unsigned(data: CrdsData) -> Self {
        Self {
            signature: Signature::default(),
            data,
        }
    }

    pub fn new_signed(data: CrdsData, keypair: &Keypair) -> Self {
        let mut value = Self::new_unsigned(data);
        value.sign(keypair);
        value
    }

    /// New random CrdsValue for tests and benchmarks.
    pub fn new_rand<R: Rng>(rng: &mut R, keypair: Option<&Keypair>) -> CrdsValue {
        match keypair {
            None => {
                let keypair = Keypair::new();
                let data = CrdsData::new_rand(rng, Some(keypair.pubkey()));
                Self::new_signed(data, &keypair)
            }
            Some(keypair) => {
                let data = CrdsData::new_rand(rng, Some(keypair.pubkey()));
                Self::new_signed(data, keypair)
            }
        }
    }

    /// Totally unsecure unverifiable wallclock of the node that generated this message
    /// Latest wallclock is always picked.
    /// This is used to time out push messages.
    pub fn wallclock(&self) -> u64 {
        match &self.data {
            CrdsData::ContactInfo(contact_info) => contact_info.wallclock,
            CrdsData::Vote(_, vote) => vote.wallclock,
            CrdsData::LowestSlot(_, obj) => obj.wallclock,
            CrdsData::SnapshotHashes(hash) => hash.wallclock,
            CrdsData::AccountsHashes(hash) => hash.wallclock,
            CrdsData::EpochSlots(_, p) => p.wallclock,
            CrdsData::LegacyVersion(version) => version.wallclock,
            CrdsData::Version(version) => version.wallclock,
            CrdsData::NodeInstance(node) => node.wallclock,
            CrdsData::DuplicateShred(_, shred) => shred.wallclock,
            CrdsData::IncrementalSnapshotHashes(hash) => hash.wallclock,
        }
    }
    pub fn pubkey(&self) -> Pubkey {
        match &self.data {
            CrdsData::ContactInfo(contact_info) => contact_info.id,
            CrdsData::Vote(_, vote) => vote.from,
            CrdsData::LowestSlot(_, slots) => slots.from,
            CrdsData::SnapshotHashes(hash) => hash.from,
            CrdsData::AccountsHashes(hash) => hash.from,
            CrdsData::EpochSlots(_, p) => p.from,
            CrdsData::LegacyVersion(version) => version.from,
            CrdsData::Version(version) => version.from,
            CrdsData::NodeInstance(node) => node.from,
            CrdsData::DuplicateShred(_, shred) => shred.from,
            CrdsData::IncrementalSnapshotHashes(hash) => hash.from,
        }
    }
    pub fn label(&self) -> CrdsValueLabel {
        match &self.data {
            CrdsData::ContactInfo(_) => CrdsValueLabel::ContactInfo(self.pubkey()),
            CrdsData::Vote(ix, _) => CrdsValueLabel::Vote(*ix, self.pubkey()),
            CrdsData::LowestSlot(_, _) => CrdsValueLabel::LowestSlot(self.pubkey()),
            CrdsData::SnapshotHashes(_) => CrdsValueLabel::SnapshotHashes(self.pubkey()),
            CrdsData::AccountsHashes(_) => CrdsValueLabel::AccountsHashes(self.pubkey()),
            CrdsData::EpochSlots(ix, _) => CrdsValueLabel::EpochSlots(*ix, self.pubkey()),
            CrdsData::LegacyVersion(_) => CrdsValueLabel::LegacyVersion(self.pubkey()),
            CrdsData::Version(_) => CrdsValueLabel::Version(self.pubkey()),
            CrdsData::NodeInstance(node) => CrdsValueLabel::NodeInstance(node.from),
            CrdsData::DuplicateShred(ix, shred) => CrdsValueLabel::DuplicateShred(*ix, shred.from),
            CrdsData::IncrementalSnapshotHashes(_) => {
                CrdsValueLabel::IncrementalSnapshotHashes(self.pubkey())
            }
        }
    }
    pub fn contact_info(&self) -> Option<&ContactInfo> {
        match &self.data {
            CrdsData::ContactInfo(contact_info) => Some(contact_info),
            _ => None,
        }
    }

    pub(crate) fn accounts_hash(&self) -> Option<&SnapshotHashes> {
        match &self.data {
            CrdsData::AccountsHashes(slots) => Some(slots),
            _ => None,
        }
    }

    pub(crate) fn epoch_slots(&self) -> Option<&EpochSlots> {
        match &self.data {
            CrdsData::EpochSlots(_, slots) => Some(slots),
            _ => None,
        }
    }

    /// Returns the size (in bytes) of a CrdsValue
    pub fn size(&self) -> u64 {
        serialized_size(&self).expect("unable to serialize contact info")
    }

    /// Returns true if, regardless of prunes, this crds-value
    /// should be pushed to the receiving node.
    pub(crate) fn should_force_push(&self, peer: &Pubkey) -> bool {
        match &self.data {
            CrdsData::NodeInstance(node) => node.from == *peer,
            _ => false,
        }
    }
}

/// Filters out an iterator of crds values, returning
/// the unique ones with the most recent wallclock.
pub(crate) fn filter_current<'a, I>(values: I) -> impl Iterator<Item = &'a CrdsValue>
where
    I: IntoIterator<Item = &'a CrdsValue>,
{
    let mut out = HashMap::new();
    for value in values {
        match out.entry(value.label()) {
            Entry::Vacant(entry) => {
                entry.insert((value, value.wallclock()));
            }
            Entry::Occupied(mut entry) => {
                let value_wallclock = value.wallclock();
                let (_, entry_wallclock) = entry.get();
                if *entry_wallclock < value_wallclock {
                    entry.insert((value, value_wallclock));
                }
            }
        }
    }
    out.into_iter().map(|(_, (v, _))| v)
}

pub(crate) fn sanitize_wallclock(wallclock: u64) -> Result<(), SanitizeError> {
    if wallclock >= MAX_WALLCLOCK {
        Err(SanitizeError::ValueOutOfBounds)
    } else {
        Ok(())
    }
}