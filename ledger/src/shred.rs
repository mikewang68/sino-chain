//! The `shred` module defines data structures and methods to pull MTU sized data frames from the
//! network. There are two types of shreds: data and coding. Data shreds contain entry information
//! while coding shreds provide redundancy to protect against dropped network packets (erasures).
//!
//! +---------------------------------------------------------------------------------------------+
//! | Data Shred                                                                                  |
//! +---------------------------------------------------------------------------------------------+
//! | common       | data       | payload                                                         |
//! | header       | header     |                                                                 |
//! |+---+---+---  |+---+---+---|+----------------------------------------------------------+----+|
//! || s | s | .   || p | f | s || data (ie ledger entries)                                 | r  ||
//! || i | h | .   || a | l | i ||                                                          | e  ||
//! || g | r | .   || r | a | z || See notes immediately after shred diagrams for an        | s  ||
//! || n | e |     || e | g | e || explanation of the "restricted" section in this payload  | t  ||
//! || a | d |     || n | s |   ||                                                          | r  ||
//! || t |   |     || t |   |   ||                                                          | i  ||
//! || u | t |     ||   |   |   ||                                                          | c  ||
//! || r | y |     || o |   |   ||                                                          | t  ||
//! || e | p |     || f |   |   ||                                                          | e  ||
//! ||   | e |     || f |   |   ||                                                          | d  ||
//! |+---+---+---  |+---+---+---+|----------------------------------------------------------+----+|
//! +---------------------------------------------------------------------------------------------+
//!
//! +---------------------------------------------------------------------------------------------+
//! | Coding Shred                                                                                |
//! +---------------------------------------------------------------------------------------------+
//! | common       | coding     | payload                                                         |
//! | header       | header     |                                                                 |
//! |+---+---+---  |+---+---+---+----------------------------------------------------------------+|
//! || s | s | .   || n | n | p || data (encoded data shred data)                                ||
//! || i | h | .   || u | u | o ||                                                               ||
//! || g | r | .   || m | m | s ||                                                               ||
//! || n | e |     ||   |   | i ||                                                               ||
//! || a | d |     || d | c | t ||                                                               ||
//! || t |   |     ||   |   | i ||                                                               ||
//! || u | t |     || s | s | o ||                                                               ||
//! || r | y |     || h | h | n ||                                                               ||
//! || e | p |     || r | r |   ||                                                               ||
//! ||   | e |     || e | e |   ||                                                               ||
//! ||   |   |     || d | d |   ||                                                               ||
//! |+---+---+---  |+---+---+---+|+--------------------------------------------------------------+|
//! +---------------------------------------------------------------------------------------------+
//!
//! Notes:
//! a) Coding shreds encode entire data shreds: both of the headers AND the payload.
//! b) Coding shreds require their own headers for identification and etc.
//! c) The erasure algorithm requires data shred and coding shred bytestreams to be equal in length.
//!
//! So, given a) - c), we must restrict data shred's payload length such that the entire coding
//! payload can fit into one coding shred / packet.

use {
    crate::{blockstore::MAX_DATA_SHREDS_PER_SLOT, erasure::Session},
    bincode::config::Options,
    num_enum::{IntoPrimitive, TryFromPrimitive},
    rayon::{prelude::*, ThreadPool},
    serde::{Deserialize, Serialize},
    entry::entry::{create_ticks, Entry},
    measure::measure::Measure,
    perf::packet::Packet,
    rayon_threadlimit::get_thread_count,
    // runtime::bank::Bank,
    sdk::{
        clock::Slot,
        feature_set,
        hash::{hashv, Hash},
        packet::PACKET_DATA_SIZE,
        pubkey::Pubkey,
        signature::{Keypair, Signature, Signer},
    },
    std::{cell::RefCell, mem::size_of},
    thiserror::Error,
};

#[derive(Default, Clone)]
pub struct ProcessShredsStats {
    // Per-slot elapsed time
    pub shredding_elapsed: u64,
    pub receive_elapsed: u64,
    pub serialize_elapsed: u64,
    pub gen_data_elapsed: u64,
    pub gen_coding_elapsed: u64,
    pub sign_coding_elapsed: u64,
    pub coding_send_elapsed: u64,
    pub get_leader_schedule_elapsed: u64,
}
impl ProcessShredsStats {
    pub fn update(&mut self, new_stats: &ProcessShredsStats) {
        self.shredding_elapsed += new_stats.shredding_elapsed;
        self.receive_elapsed += new_stats.receive_elapsed;
        self.serialize_elapsed += new_stats.serialize_elapsed;
        self.gen_data_elapsed += new_stats.gen_data_elapsed;
        self.gen_coding_elapsed += new_stats.gen_coding_elapsed;
        self.sign_coding_elapsed += new_stats.sign_coding_elapsed;
        self.coding_send_elapsed += new_stats.gen_coding_elapsed;
        self.get_leader_schedule_elapsed += new_stats.get_leader_schedule_elapsed;
    }
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

pub type Nonce = u32;

/// The following constants are computed by hand, and hardcoded.
/// `test_shred_constants` ensures that the values are correct.
/// Constants are used over lazy_static for performance reasons.
pub const SIZE_OF_COMMON_SHRED_HEADER: usize = 83;
pub const SIZE_OF_DATA_SHRED_HEADER: usize = 5;
pub const SIZE_OF_CODING_SHRED_HEADER: usize = 6;
pub const SIZE_OF_SIGNATURE: usize = 64;
pub const SIZE_OF_SHRED_TYPE: usize = 1;
pub const SIZE_OF_SHRED_SLOT: usize = 8;
pub const SIZE_OF_SHRED_INDEX: usize = 4;
pub const SIZE_OF_NONCE: usize = 4;
pub const SIZE_OF_CODING_SHRED_HEADERS: usize =
    SIZE_OF_COMMON_SHRED_HEADER + SIZE_OF_CODING_SHRED_HEADER;
pub const SIZE_OF_DATA_SHRED_PAYLOAD: usize = PACKET_DATA_SIZE
    - SIZE_OF_COMMON_SHRED_HEADER
    - SIZE_OF_DATA_SHRED_HEADER
    - SIZE_OF_CODING_SHRED_HEADERS
    - SIZE_OF_NONCE;

pub const OFFSET_OF_SHRED_TYPE: usize = SIZE_OF_SIGNATURE;
pub const OFFSET_OF_SHRED_SLOT: usize = SIZE_OF_SIGNATURE + SIZE_OF_SHRED_TYPE;
pub const OFFSET_OF_SHRED_INDEX: usize = OFFSET_OF_SHRED_SLOT + SIZE_OF_SHRED_SLOT;
pub const SHRED_PAYLOAD_SIZE: usize = PACKET_DATA_SIZE - SIZE_OF_NONCE;

thread_local!(static PAR_THREAD_POOL: RefCell<ThreadPool> = RefCell::new(rayon::ThreadPoolBuilder::new()
                    .num_threads(get_thread_count())
                    .thread_name(|ix| format!("shredder_{}", ix))
                    .build()
                    .unwrap()));

pub const MAX_DATA_SHREDS_PER_FEC_BLOCK: u32 = 32;

pub const SHRED_TICK_REFERENCE_MASK: u8 = 0b0011_1111;
const LAST_SHRED_IN_SLOT: u8 = 0b1000_0000;
pub const DATA_COMPLETE_SHRED: u8 = 0b0100_0000;

#[derive(Error, Debug)]
pub enum ShredError {
    #[error("invalid shred type")]
    InvalidShredType,

    #[error("invalid FEC rate; must be 0.0 < {0} < 1.0")]
    InvalidFecRate(f32),

    #[error("slot too low; current slot {slot} must be above parent slot {parent_slot}, but the difference must be below u16::MAX")]
    SlotTooLow { slot: Slot, parent_slot: Slot },

    #[error("serialization error")]
    Serialize(#[from] Box<bincode::ErrorKind>),

    #[error(
        "invalid parent offset; parent_offset {parent_offset} must be larger than slot {slot}"
    )]
    InvalidParentOffset { slot: Slot, parent_offset: u16 },

    #[error("invalid payload")]
    InvalidPayload,
}

pub type Result<T> = std::result::Result<T, ShredError>;

#[repr(u8)]
#[derive(
    Clone,
    Copy,
    Debug,
    Eq,
    Hash,
    PartialEq,
    AbiEnumVisitor,
    AbiExample,
    Deserialize,
    IntoPrimitive,
    Serialize,
    TryFromPrimitive,
)]
#[serde(into = "u8", try_from = "u8")]
pub enum ShredType {
    Data = 0b1010_0101,
    Code = 0b0101_1010,
}

impl Default for ShredType {
    fn default() -> Self {
        ShredType::Data
    }
}

/// A common header that is present in data and code shred headers
#[derive(Serialize, Clone, Deserialize, Default, PartialEq, Debug)]
pub struct ShredCommonHeader {
    pub signature: Signature,
    pub shred_type: ShredType,
    pub slot: Slot,
    pub index: u32,
    pub version: u16,
    pub fec_set_index: u32,
}

/// The data shred header has parent offset and flags
#[derive(Serialize, Clone, Default, Deserialize, PartialEq, Debug)]
pub struct DataShredHeader {
    pub parent_offset: u16,
    pub flags: u8,
    pub size: u16,
}

/// The coding shred header has FEC information
#[derive(Serialize, Clone, Default, Deserialize, PartialEq, Debug)]
pub struct CodingShredHeader {
    pub num_data_shreds: u16,
    pub num_coding_shreds: u16,
    pub position: u16,
}

/// 900字节 ipv6 不确定
#[derive(Clone, Debug, PartialEq)]
pub struct Shred { 
    pub common_header: ShredCommonHeader,
    pub data_header: DataShredHeader,
    pub coding_header: CodingShredHeader,
    pub payload: Vec<u8>, //最大？
}

/// Tuple which uniquely identifies a shred should it exists.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ShredId(Slot, /*shred index:*/ u32, ShredType);

impl ShredId {
    pub(crate) fn new(slot: Slot, index: u32, shred_type: ShredType) -> ShredId {
        ShredId(slot, index, shred_type)
    }

    pub(crate) fn unwrap(&self) -> (Slot, /*shred index:*/ u32, ShredType) {
        (self.0, self.1, self.2)
    }
}

/// Tuple which identifies erasure coding set that the shred belongs to.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct ErasureSetId(Slot, /*fec_set_index:*/ u32);

impl ErasureSetId {
    pub(crate) fn slot(&self) -> Slot {
        self.0
    }

    // Storage key for ErasureMeta in blockstore db.
    pub(crate) fn store_key(&self) -> (Slot, /*fec_set_index:*/ u64) {
        (self.0, u64::from(self.1))
    }
}

impl Shred {
    fn deserialize_obj<'de, T>(index: &mut usize, size: usize, buf: &'de [u8]) -> bincode::Result<T>
    where
        T: Deserialize<'de>,
    {
        let end = std::cmp::min(*index + size, buf.len());
        let ret = bincode::options()
            .with_limit(PACKET_DATA_SIZE as u64)
            .with_fixint_encoding()
            .allow_trailing_bytes()
            .deserialize(&buf[*index..end])?;
        *index += size;
        Ok(ret)
    }

    fn serialize_obj_into<'de, T>(
        index: &mut usize,
        size: usize,
        buf: &'de mut [u8],
        obj: &T,
    ) -> bincode::Result<()>
    where
        T: Serialize,
    {
        bincode::serialize_into(&mut buf[*index..*index + size], obj)?;
        *index += size;
        Ok(())
    }

    pub fn copy_to_packet(&self, packet: &mut Packet) {
        let len = self.payload.len();
        packet.data[..len].copy_from_slice(&self.payload[..]);
        packet.meta.size = len;
    }

    pub fn new_from_data(
        slot: Slot,
        index: u32,
        parent_offset: u16,
        data: Option<&[u8]>,
        is_last_data: bool,
        is_last_in_slot: bool,
        reference_tick: u8,
        version: u16,
        fec_set_index: u32,
    ) -> Self {
        let payload_size = SHRED_PAYLOAD_SIZE;
        let mut payload = vec![0; payload_size];
        let common_header = ShredCommonHeader {
            slot,
            index,
            version,
            fec_set_index,
            ..ShredCommonHeader::default()
        };

        let size = (data.map(|d| d.len()).unwrap_or(0)
            + SIZE_OF_DATA_SHRED_HEADER
            + SIZE_OF_COMMON_SHRED_HEADER) as u16;
        let mut data_header = DataShredHeader {
            parent_offset,
            flags: reference_tick.min(SHRED_TICK_REFERENCE_MASK),
            size,
        };

        if is_last_data {
            data_header.flags |= DATA_COMPLETE_SHRED
        }

        if is_last_in_slot {
            data_header.flags |= LAST_SHRED_IN_SLOT
        }

        let mut start = 0;
        Self::serialize_obj_into(
            &mut start,
            SIZE_OF_COMMON_SHRED_HEADER,
            &mut payload,
            &common_header,
        )
        .expect("Failed to write common header into shred buffer");

        Self::serialize_obj_into(
            &mut start,
            SIZE_OF_DATA_SHRED_HEADER,
            &mut payload,
            &data_header,
        )
        .expect("Failed to write data header into shred buffer");

        if let Some(data) = data {
            payload[start..start + data.len()].clone_from_slice(data);
        }

        Self {
            common_header,
            data_header,
            coding_header: CodingShredHeader::default(),
            payload,
        }
    }

    pub fn new_from_serialized_shred(mut payload: Vec<u8>) -> Result<Self> {
        let mut start = 0;
        let common_header: ShredCommonHeader =
            Self::deserialize_obj(&mut start, SIZE_OF_COMMON_SHRED_HEADER, &payload)?;

        // Shreds should be padded out to SHRED_PAYLOAD_SIZE
        // so that erasure generation/recovery works correctly
        // But only the data_header.size is stored in blockstore.
        payload.resize(SHRED_PAYLOAD_SIZE, 0);
        let (data_header, coding_header) = match common_header.shred_type {
            ShredType::Code => {
                let coding_header: CodingShredHeader =
                    Self::deserialize_obj(&mut start, SIZE_OF_CODING_SHRED_HEADER, &payload)?;
                (DataShredHeader::default(), coding_header)
            }
            ShredType::Data => {
                let data_header: DataShredHeader =
                    Self::deserialize_obj(&mut start, SIZE_OF_DATA_SHRED_HEADER, &payload)?;
                (data_header, CodingShredHeader::default())
            }
        };
        let shred = Self {
            common_header,
            data_header,
            coding_header,
            payload,
        };
        shred
            .sanitize()
            .then_some(shred)
            .ok_or(ShredError::InvalidPayload)
    }

    pub fn new_empty_coding(
        slot: Slot,
        index: u32,
        fec_set_index: u32,
        num_data: u16,
        num_code: u16,
        position: u16,
        version: u16,
    ) -> Self {
        let (header, coding_header) = Shredder::new_coding_shred_header(
            slot,
            index,
            fec_set_index,
            num_data,
            num_code,
            position,
            version,
        );
        Shred::new_empty_from_header(header, DataShredHeader::default(), coding_header)
    }

    pub fn new_empty_from_header(
        common_header: ShredCommonHeader,
        data_header: DataShredHeader,
        coding_header: CodingShredHeader,
    ) -> Self {
        let mut payload = vec![0; SHRED_PAYLOAD_SIZE];
        let mut start = 0;
        Self::serialize_obj_into(
            &mut start,
            SIZE_OF_COMMON_SHRED_HEADER,
            &mut payload,
            &common_header,
        )
        .expect("Failed to write header into shred buffer");
        match common_header.shred_type {
            ShredType::Data => Self::serialize_obj_into(
                &mut start,
                SIZE_OF_DATA_SHRED_HEADER,
                &mut payload,
                &data_header,
            )
            .expect("Failed to write data header into shred buffer"),
            ShredType::Code => Self::serialize_obj_into(
                &mut start,
                SIZE_OF_CODING_SHRED_HEADER,
                &mut payload,
                &coding_header,
            )
            .expect("Failed to write coding header into shred buffer"),
        };
        Shred {
            common_header,
            data_header,
            coding_header,
            payload,
        }
    }

    pub fn new_empty_data_shred() -> Self {
        Self::new_empty_from_header(
            ShredCommonHeader::default(),
            DataShredHeader::default(),
            CodingShredHeader::default(),
        )
    }

    /// Unique identifier for each shred.
    pub fn id(&self) -> ShredId {
        ShredId(self.slot(), self.index(), self.shred_type())
    }

    pub fn slot(&self) -> Slot {
        self.common_header.slot
    }

    pub fn parent(&self) -> Result<Slot> {
        match self.shred_type() {
            ShredType::Data => {
                let slot = self.slot();
                let parent_offset = Slot::from(self.data_header.parent_offset);
                if parent_offset == 0 && slot != 0 {
                    return Err(ShredError::InvalidParentOffset {
                        slot,
                        parent_offset: 0,
                    });
                }
                slot.checked_sub(parent_offset)
                    .ok_or(ShredError::InvalidParentOffset {
                        slot,
                        parent_offset: self.data_header.parent_offset,
                    })
            }
            ShredType::Code => Err(ShredError::InvalidShredType),
        }
    }

    pub fn index(&self) -> u32 {
        self.common_header.index
    }

    pub(crate) fn fec_set_index(&self) -> u32 {
        self.common_header.fec_set_index
    }

    pub(crate) fn first_coding_index(&self) -> Option<u32> {
        match self.shred_type() {
            ShredType::Data => None,
            ShredType::Code => {
                let position = u32::from(self.coding_header.position);
                self.index().checked_sub(position)
            }
        }
    }

    // Returns true if the shred passes sanity checks.
    pub(crate) fn sanitize(&self) -> bool {
        self.erasure_block_index().is_some()
            && match self.shred_type() {
                ShredType::Data => {
                    self.parent().is_ok()
                        && usize::from(self.data_header.size) <= self.payload.len()
                }
                ShredType::Code => {
                    u32::from(self.coding_header.num_coding_shreds)
                        <= 8 * MAX_DATA_SHREDS_PER_FEC_BLOCK
                }
            }
    }

    pub fn version(&self) -> u16 {
        self.common_header.version
    }

    // Identifier for the erasure coding set that the shred belongs to.
    pub(crate) fn erasure_set(&self) -> ErasureSetId {
        ErasureSetId(self.slot(), self.fec_set_index())
    }

    // Returns the block index within the erasure coding set.
    fn erasure_block_index(&self) -> Option<usize> {
        match self.shred_type() {
            ShredType::Data => {
                let index = self.index().checked_sub(self.fec_set_index())?;
                usize::try_from(index).ok()
            }
            ShredType::Code => {
                // Assert that the last shred index in the erasure set does not
                // overshoot u32.
                self.fec_set_index().checked_add(u32::from(
                    self.coding_header.num_data_shreds.checked_sub(1)?,
                ))?;
                self.first_coding_index()?.checked_add(u32::from(
                    self.coding_header.num_coding_shreds.checked_sub(1)?,
                ))?;
                let num_data_shreds = usize::from(self.coding_header.num_data_shreds);
                let num_coding_shreds = usize::from(self.coding_header.num_coding_shreds);
                let position = usize::from(self.coding_header.position);
                let fec_set_size = num_data_shreds.checked_add(num_coding_shreds)?;
                let index = position.checked_add(num_data_shreds)?;
                (index < fec_set_size).then_some(index)
            }
        }
    }

    // Returns the portion of the shred's payload which is erasure coded.
    fn erasure_block(self) -> Vec<u8> {
        let shred_type = self.shred_type();
        let mut block = self.payload;
        match shred_type {
            ShredType::Data => {
                // SIZE_OF_CODING_SHRED_HEADERS bytes at the end of data shreds
                // is never used and is not part of erasure coding.
                let size = SHRED_PAYLOAD_SIZE - SIZE_OF_CODING_SHRED_HEADERS;
                block.resize(size, 0u8);
            }
            ShredType::Code => {
                // SIZE_OF_CODING_SHRED_HEADERS bytes at the begining of the
                // coding shreds contains the header and is not part of erasure
                // coding.
                let offset = SIZE_OF_CODING_SHRED_HEADERS.min(block.len());
                block.drain(..offset);
            }
        }
        block
    }

    pub fn set_index(&mut self, index: u32) {
        self.common_header.index = index;
        Self::serialize_obj_into(
            &mut 0,
            SIZE_OF_COMMON_SHRED_HEADER,
            &mut self.payload,
            &self.common_header,
        )
        .unwrap();
    }

    pub fn set_slot(&mut self, slot: Slot) {
        self.common_header.slot = slot;
        Self::serialize_obj_into(
            &mut 0,
            SIZE_OF_COMMON_SHRED_HEADER,
            &mut self.payload,
            &self.common_header,
        )
        .unwrap();
    }

    pub fn signature(&self) -> Signature {
        self.common_header.signature
    }

    // pub fn seed(&self, leader_pubkey: Pubkey, root_bank: &Bank) -> [u8; 32] {
    //     if add_shred_type_to_shred_seed(self.slot(), root_bank) {
    //         hashv(&[
    //             &self.slot().to_le_bytes(),
    //             &u8::from(self.shred_type()).to_le_bytes(),
    //             &self.index().to_le_bytes(),
    //             &leader_pubkey.to_bytes(),
    //         ])
    //     } else {
    //         hashv(&[
    //             &self.slot().to_le_bytes(),
    //             &self.index().to_le_bytes(),
    //             &leader_pubkey.to_bytes(),
    //         ])
    //     }
    //     .to_bytes()
    // }

    #[inline]
    pub fn shred_type(&self) -> ShredType {
        self.common_header.shred_type
    }

    pub fn is_data(&self) -> bool {
        self.shred_type() == ShredType::Data
    }
    pub fn is_code(&self) -> bool {
        self.shred_type() == ShredType::Code
    }

    pub fn last_in_slot(&self) -> bool {
        if self.is_data() {
            self.data_header.flags & LAST_SHRED_IN_SLOT == LAST_SHRED_IN_SLOT
        } else {
            false
        }
    }

    /// This is not a safe function. It only changes the meta information.
    /// Use this only for test code which doesn't care about actual shred
    pub fn set_last_in_slot(&mut self) {
        if self.is_data() {
            self.data_header.flags |= LAST_SHRED_IN_SLOT
        }
    }

    #[cfg(test)]
    pub fn unset_data_complete(&mut self) {
        if self.is_data() {
            self.data_header.flags &= !DATA_COMPLETE_SHRED;
        }

        // Data header starts after the shred common header
        let mut start = SIZE_OF_COMMON_SHRED_HEADER;
        let size_of_data_shred_header = SIZE_OF_DATA_SHRED_HEADER;
        Self::serialize_obj_into(
            &mut start,
            size_of_data_shred_header,
            &mut self.payload,
            &self.data_header,
        )
        .expect("Failed to write data header into shred buffer");
    }

    pub fn data_complete(&self) -> bool {
        if self.is_data() {
            self.data_header.flags & DATA_COMPLETE_SHRED == DATA_COMPLETE_SHRED
        } else {
            false
        }
    }

    pub fn reference_tick(&self) -> u8 {
        if self.is_data() {
            self.data_header.flags & SHRED_TICK_REFERENCE_MASK
        } else {
            SHRED_TICK_REFERENCE_MASK
        }
    }

    // Get slot from a shred packet with partial deserialize
    pub fn get_slot_from_packet(p: &Packet) -> Option<Slot> {
        let slot_start = OFFSET_OF_SHRED_SLOT;
        let slot_end = slot_start + SIZE_OF_SHRED_SLOT;
        p.deserialize_slice(slot_start..slot_end).ok()
    }

    pub fn reference_tick_from_data(data: &[u8]) -> u8 {
        let flags = data[SIZE_OF_COMMON_SHRED_HEADER + SIZE_OF_DATA_SHRED_HEADER
            - size_of::<u8>()
            - size_of::<u16>()];
        flags & SHRED_TICK_REFERENCE_MASK
    }

    pub fn verify(&self, pubkey: &Pubkey) -> bool {
        self.signature()
            .verify(pubkey.as_ref(), &self.payload[SIZE_OF_SIGNATURE..])
    }
}

#[derive(Debug)]
pub struct Shredder {
    pub slot: Slot,
    pub parent_slot: Slot,
    version: u16,
    pub signing_coding_time: u128,
    reference_tick: u8,
}

impl Shredder {
    pub fn new(slot: Slot, parent_slot: Slot, reference_tick: u8, version: u16) -> Result<Self> {
        if slot < parent_slot || slot - parent_slot > u64::from(std::u16::MAX) {
            Err(ShredError::SlotTooLow { slot, parent_slot })
        } else {
            Ok(Self {
                slot,
                parent_slot,
                signing_coding_time: 0,
                reference_tick,
                version,
            })
        }
    }

    pub fn entries_to_shreds(
        &self,
        keypair: &Keypair,
        entries: &[Entry],
        is_last_in_slot: bool, //t
        next_shred_index: u32, // 0
        next_code_index: u32, // 0
    ) -> (
        Vec<Shred>, // data shreds
        Vec<Shred>, // coding shreds
    ) {
        let mut stats = ProcessShredsStats::default();
        let data_shreds = self.entries_to_data_shreds(
            keypair,
            entries,
            is_last_in_slot, //t
            next_shred_index, //0 
            next_shred_index, // fec_set_offset //0
            &mut stats, // 0
        );
        let coding_shreds = Self::data_shreds_to_coding_shreds(
            keypair,
            &data_shreds,
            is_last_in_slot,
            next_code_index,
            &mut stats,
        )
        .unwrap();
        (data_shreds, coding_shreds)
    }

    // Each FEC block has maximum MAX_DATA_SHREDS_PER_FEC_BLOCK shreds.
    // "FEC set index" is the index of first data shred in that FEC block.
    // Shred indices with the same value of:
    //   (shred_index - fec_set_offset) / MAX_DATA_SHREDS_PER_FEC_BLOCK
    // belong to the same FEC set.
    pub fn fec_set_index(shred_index: u32, fec_set_offset: u32) -> Option<u32> {
        let diff = shred_index.checked_sub(fec_set_offset)?;
        Some(shred_index - diff % MAX_DATA_SHREDS_PER_FEC_BLOCK)
    }

    pub fn entries_to_data_shreds(
        &self,
        keypair: &Keypair,
        entries: &[Entry],
        is_last_in_slot: bool,
        next_shred_index: u32,
        // Shred index offset at which FEC sets are generated.
        fec_set_offset: u32,
        process_stats: &mut ProcessShredsStats,
    ) -> Vec<Shred> {
        let mut serialize_time = Measure::start("shred_serialize");
        // 序列化entries
        let serialized_shreds =
            bincode::serialize(entries).expect("Expect to serialize all entries");
        serialize_time.stop();

        let mut gen_data_time = Measure::start("shred_gen_data_time");
        let payload_capacity = SIZE_OF_DATA_SHRED_PAYLOAD; //1051
        // Integer division to ensure we have enough shreds to fit all the data
        // 切片数量
        let num_shreds = (serialized_shreds.len() + payload_capacity - 1) / payload_capacity;
        let last_shred_index = next_shred_index + num_shreds as u32 - 1;
        // 1) Generate data shreds
        let make_data_shred = |shred_index: u32, data| {
            let is_last_data = shred_index == last_shred_index;
            let is_last_in_slot = is_last_data && is_last_in_slot;
            let parent_offset = self.slot - self.parent_slot;
            let fec_set_index = Self::fec_set_index(shred_index, fec_set_offset);
            let mut shred = Shred::new_from_data(
                self.slot,
                shred_index,
                parent_offset as u16,
                Some(data),
                is_last_data,
                is_last_in_slot,
                self.reference_tick,
                self.version,
                fec_set_index.unwrap(),
            );
            Shredder::sign_shred(keypair, &mut shred);
            shred
        };
        let data_shreds: Vec<Shred> = PAR_THREAD_POOL.with(|thread_pool| {
            thread_pool.borrow().install(|| {
                serialized_shreds
                    .par_chunks(payload_capacity)
                    .enumerate()
                    .map(|(i, shred_data)| {
                        let shred_index = next_shred_index + i as u32;
                        make_data_shred(shred_index, shred_data)
                    })
                    .collect()
            })
        });
        gen_data_time.stop();

        process_stats.serialize_elapsed += serialize_time.as_us();
        process_stats.gen_data_elapsed += gen_data_time.as_us();

        data_shreds
    }

    pub fn data_shreds_to_coding_shreds(
        keypair: &Keypair,
        data_shreds: &[Shred],
        is_last_in_slot: bool,
        next_code_index: u32,
        process_stats: &mut ProcessShredsStats,
    ) -> Result<Vec<Shred>> {
        if data_shreds.is_empty() {
            return Ok(Vec::default());
        }
        let mut gen_coding_time = Measure::start("gen_coding_shreds");
        // 1) Generate coding shreds
        let mut coding_shreds: Vec<_> = PAR_THREAD_POOL.with(|thread_pool| {
            thread_pool.borrow().install(|| {
                data_shreds
                    .par_chunks(MAX_DATA_SHREDS_PER_FEC_BLOCK as usize)
                    .enumerate()
                    .flat_map(|(i, shred_data_batch)| {
                        // Assumption here is that, for now, each fec block has
                        // as many coding shreds as data shreds (except for the
                        // last one in the slot).
                        // TODO: tie this more closely with
                        // generate_coding_shreds.
                        let next_code_index = next_code_index
                            .checked_add(
                                u32::try_from(i)
                                    .unwrap()
                                    .checked_mul(MAX_DATA_SHREDS_PER_FEC_BLOCK)
                                    .unwrap(),
                            )
                            .unwrap();
                        Shredder::generate_coding_shreds(
                            shred_data_batch,
                            is_last_in_slot,
                            next_code_index,
                        )
                    })
                    .collect()
            })
        });
        gen_coding_time.stop();

        let mut sign_coding_time = Measure::start("sign_coding_shreds");
        // 2) Sign coding shreds
        PAR_THREAD_POOL.with(|thread_pool| {
            thread_pool.borrow().install(|| {
                coding_shreds.par_iter_mut().for_each(|coding_shred| {
                    Shredder::sign_shred(keypair, coding_shred);
                })
            })
        });
        sign_coding_time.stop();

        process_stats.gen_coding_elapsed += gen_coding_time.as_us();
        process_stats.sign_coding_elapsed += sign_coding_time.as_us();
        Ok(coding_shreds)
    }

    pub fn sign_shred(signer: &Keypair, shred: &mut Shred) {
        let signature = signer.sign_message(&shred.payload[SIZE_OF_SIGNATURE..]);
        bincode::serialize_into(&mut shred.payload[..SIZE_OF_SIGNATURE], &signature)
            .expect("Failed to generate serialized signature");
        shred.common_header.signature = signature;
    }

    pub fn new_coding_shred_header(
        slot: Slot,
        index: u32,
        fec_set_index: u32,
        num_data_shreds: u16,
        num_coding_shreds: u16,
        position: u16,
        version: u16,
    ) -> (ShredCommonHeader, CodingShredHeader) {
        let header = ShredCommonHeader {
            shred_type: ShredType::Code,
            index,
            slot,
            version,
            fec_set_index,
            ..ShredCommonHeader::default()
        };
        (
            header,
            CodingShredHeader {
                num_data_shreds,
                num_coding_shreds,
                position,
            },
        )
    }

    /// Generates coding shreds for the data shreds in the current FEC set
    pub fn generate_coding_shreds(
        data: &[Shred],
        is_last_in_slot: bool,
        next_code_index: u32,
    ) -> Vec<Shred> {
        const PAYLOAD_ENCODE_SIZE: usize = SHRED_PAYLOAD_SIZE - SIZE_OF_CODING_SHRED_HEADERS;
        let ShredCommonHeader {
            slot,
            index,
            version,
            fec_set_index,
            ..
        } = data.first().unwrap().common_header;
        assert_eq!(fec_set_index, index);
        assert!(data.iter().all(|shred| shred.common_header.slot == slot
            && shred.common_header.version == version
            && shred.fec_set_index() == fec_set_index));
        let num_data = data.len();
        let num_coding = if is_last_in_slot {
            (2 * MAX_DATA_SHREDS_PER_FEC_BLOCK as usize)
                .saturating_sub(num_data)
                .max(num_data)
        } else {
            num_data
        };
        let data: Vec<_> = data
            .iter()
            .map(|shred| &shred.payload[..PAYLOAD_ENCODE_SIZE])
            .collect();
        let mut parity = vec![vec![0u8; PAYLOAD_ENCODE_SIZE]; num_coding];
        Session::new(num_data, num_coding)
            .unwrap()
            .encode(&data, &mut parity[..])
            .unwrap();
        let num_data = u16::try_from(num_data).unwrap();
        let num_coding = u16::try_from(num_coding).unwrap();
        parity
            .iter()
            .enumerate()
            .map(|(i, parity)| {
                let index = next_code_index + u32::try_from(i).unwrap();
                let mut shred = Shred::new_empty_coding(
                    slot,
                    index,
                    fec_set_index,
                    num_data,
                    num_coding,
                    u16::try_from(i).unwrap(), // position
                    version,
                );
                shred.payload[SIZE_OF_CODING_SHRED_HEADERS..].copy_from_slice(parity);
                shred
            })
            .collect()
    }

    pub fn try_recovery(
        shreds: Vec<Shred>,
    ) -> std::result::Result<Vec<Shred>, reed_solomon_erasure::Error> {
        use reed_solomon_erasure::Error::InvalidIndex;
        Self::verify_consistent_shred_payload_sizes("try_recovery()", &shreds)?;
        let (slot, fec_set_index) = match shreds.first() {
            None => return Ok(Vec::default()),
            Some(shred) => (shred.slot(), shred.fec_set_index()),
        };
        let (num_data_shreds, num_coding_shreds) = match shreds.iter().find(|shred| shred.is_code())
        {
            None => return Ok(Vec::default()),
            Some(shred) => (
                shred.coding_header.num_data_shreds,
                shred.coding_header.num_coding_shreds,
            ),
        };
        debug_assert!(shreds
            .iter()
            .all(|shred| shred.slot() == slot && shred.fec_set_index() == fec_set_index));
        debug_assert!(shreds
            .iter()
            .filter(|shred| shred.is_code())
            .all(
                |shred| shred.coding_header.num_data_shreds == num_data_shreds
                    && shred.coding_header.num_coding_shreds == num_coding_shreds
            ));
        let num_data_shreds = num_data_shreds as usize;
        let num_coding_shreds = num_coding_shreds as usize;
        let fec_set_size = num_data_shreds + num_coding_shreds;
        if num_coding_shreds == 0 || shreds.len() >= fec_set_size {
            return Ok(Vec::default());
        }
        // Mask to exclude data shreds already received from the return value.
        let mut mask = vec![false; num_data_shreds];
        let mut blocks = vec![None; fec_set_size];
        for shred in shreds {
            let index = match shred.erasure_block_index() {
                Some(index) if index < fec_set_size => index,
                _ => return Err(InvalidIndex),
            };
            blocks[index] = Some(shred.erasure_block());
            if index < num_data_shreds {
                mask[index] = true;
            }
        }
        Session::new(num_data_shreds, num_coding_shreds)?.decode_blocks(&mut blocks)?;
        let recovered_data = mask
            .into_iter()
            .zip(blocks)
            .filter(|(mask, _)| !mask)
            .filter_map(|(_, block)| Shred::new_from_serialized_shred(block?).ok())
            .filter(|shred| {
                shred.slot() == slot
                    && shred.is_data()
                    && match shred.erasure_block_index() {
                        Some(index) => index < num_data_shreds,
                        None => false,
                    }
            })
            .collect();
        Ok(recovered_data)
    }

    /// Combines all shreds to recreate the original buffer
    pub fn deshred(shreds: &[Shred]) -> std::result::Result<Vec<u8>, reed_solomon_erasure::Error> {
        use reed_solomon_erasure::Error::TooFewDataShards;
        const SHRED_DATA_OFFSET: usize = SIZE_OF_COMMON_SHRED_HEADER + SIZE_OF_DATA_SHRED_HEADER;
        Self::verify_consistent_shred_payload_sizes("deshred()", shreds)?;
        let index = shreds.first().ok_or(TooFewDataShards)?.index();
        let aligned = shreds.iter().zip(index..).all(|(s, i)| s.index() == i);
        let data_complete = {
            let shred = shreds.last().unwrap();
            shred.data_complete() || shred.last_in_slot()
        };
        if !data_complete || !aligned {
            return Err(TooFewDataShards);
        }
        let data: Vec<_> = shreds
            .iter()
            .flat_map(|shred| {
                let size = shred.data_header.size as usize;
                let size = shred.payload.len().min(size);
                let offset = SHRED_DATA_OFFSET.min(size);
                shred.payload[offset..size].iter()
            })
            .copied()
            .collect();
        if data.is_empty() {
            // For backward compatibility. This is needed when the data shred
            // payload is None, so that deserializing to Vec<Entry> results in
            // an empty vector.
            Ok(vec![0u8; SIZE_OF_DATA_SHRED_PAYLOAD])
        } else {
            Ok(data)
        }
    }

    fn verify_consistent_shred_payload_sizes(
        caller: &str,
        shreds: &[Shred],
    ) -> std::result::Result<(), reed_solomon_erasure::Error> {
        if shreds.is_empty() {
            return Err(reed_solomon_erasure::Error::TooFewShardsPresent);
        }
        let slot = shreds[0].slot();
        for shred in shreds {
            if shred.payload.len() != SHRED_PAYLOAD_SIZE {
                error!(
                    "{} Shreds for slot: {} are inconsistent sizes. Expected: {} actual: {}",
                    caller,
                    slot,
                    SHRED_PAYLOAD_SIZE,
                    shred.payload.len()
                );
                return Err(reed_solomon_erasure::Error::IncorrectShardSize);
            }
        }

        Ok(())
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub struct ShredFetchStats {
    pub index_overrun: usize,
    pub shred_count: usize,
    pub index_bad_deserialize: usize,
    pub index_out_of_bounds: usize,
    pub slot_bad_deserialize: usize,
    pub duplicate_shred: usize,
    pub slot_out_of_range: usize,
    pub bad_shred_type: usize,
}

// Get slot, index, and type from a packet with partial deserialize
pub fn get_shred_slot_index_type(
    p: &Packet,
    stats: &mut ShredFetchStats,
) -> Option<(Slot, u32, ShredType)> {
    let index_start = OFFSET_OF_SHRED_INDEX;
    let index_end = index_start + SIZE_OF_SHRED_INDEX;
    let slot_start = OFFSET_OF_SHRED_SLOT;
    let slot_end = slot_start + SIZE_OF_SHRED_SLOT;

    debug_assert!(index_end > slot_end);
    debug_assert!(index_end > OFFSET_OF_SHRED_TYPE);

    if index_end > p.meta.size {
        stats.index_overrun += 1;
        return None;
    }

    let index = match p.deserialize_slice(index_start..index_end) {
        Ok(x) => x,
        Err(_e) => {
            stats.index_bad_deserialize += 1;
            return None;
        }
    };

    if index >= MAX_DATA_SHREDS_PER_SLOT as u32 {
        stats.index_out_of_bounds += 1;
        return None;
    }

    let slot = match p.deserialize_slice(slot_start..slot_end) {
        Ok(x) => x,
        Err(_e) => {
            stats.slot_bad_deserialize += 1;
            return None;
        }
    };

    let shred_type = match ShredType::try_from(p.data[OFFSET_OF_SHRED_TYPE]) {
        Err(_) => {
            stats.bad_shred_type += 1;
            return None;
        }
        Ok(shred_type) => shred_type,
    };
    Some((slot, index, shred_type))
}

pub fn max_ticks_per_n_shreds(num_shreds: u64, shred_data_size: Option<usize>) -> u64 {
    let ticks = create_ticks(1, 0, Hash::default());
    max_entries_per_n_shred(&ticks[0], num_shreds, shred_data_size)
}

pub fn max_entries_per_n_shred(
    entry: &Entry,
    num_shreds: u64,
    shred_data_size: Option<usize>,
) -> u64 {
    let shred_data_size = shred_data_size.unwrap_or(SIZE_OF_DATA_SHRED_PAYLOAD) as u64;
    let vec_size = bincode::serialized_size(&vec![entry]).unwrap();
    let entry_size = bincode::serialized_size(entry).unwrap();
    let count_size = vec_size - entry_size;

    (shred_data_size * num_shreds - count_size) / entry_size
}

pub fn verify_test_data_shred(
    shred: &Shred,
    index: u32,
    slot: Slot,
    parent: Slot,
    pk: &Pubkey,
    verify: bool,
    is_last_in_slot: bool,
    is_last_data: bool,
) {
    assert_eq!(shred.payload.len(), SHRED_PAYLOAD_SIZE);
    assert!(shred.is_data());
    assert_eq!(shred.index(), index);
    assert_eq!(shred.slot(), slot);
    assert_eq!(shred.parent().unwrap(), parent);
    assert_eq!(verify, shred.verify(pk));
    if is_last_in_slot {
        assert!(shred.last_in_slot());
    } else {
        assert!(!shred.last_in_slot());
    }
    if is_last_data {
        assert!(shred.data_complete());
    } else {
        assert!(!shred.data_complete());
    }
}

// fn add_shred_type_to_shred_seed(shred_slot: Slot, bank: &Bank) -> bool {
//     let feature_slot = bank
//         .feature_set
//         .activated_slot(&feature_set::add_shred_type_to_shred_seed::id());
//     match feature_slot {
//         None => false,
//         Some(feature_slot) => {
//             let epoch_schedule = bank.epoch_schedule();
//             let feature_epoch = epoch_schedule.get_epoch(feature_slot);
//             let shred_epoch = epoch_schedule.get_epoch(shred_slot);
//             feature_epoch < shred_epoch
//         }
//     }
// }

