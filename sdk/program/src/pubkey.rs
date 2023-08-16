#![allow(clippy::integer_arithmetic)]
use {
    crate::{decode_error::DecodeError, hash::hashv, wasm_bindgen},
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    bytemuck::{Pod, Zeroable},
    num_derive::{FromPrimitive, ToPrimitive},
    std::{
        convert::{Infallible, TryFrom},
        fmt, mem,
        str::FromStr,
    },
    thiserror::Error,
};

/// Number of bytes in a pubkey
pub const PUBKEY_BYTES: usize = 32;
/// maximum length of derived `Pubkey` seed
pub const MAX_SEED_LEN: usize = 32;
/// Maximum number of seeds
pub const MAX_SEEDS: usize = 16;
/// Maximum string length of a base58 encoded pubkey
const MAX_BASE58_LEN: usize = 44;

const PDA_MARKER: &[u8; 21] = b"ProgramDerivedAddress";

#[derive(Error, Debug, Serialize, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum PubkeyError {
    /// Length of the seed is too long for address generation
    #[error("Length of the seed is too long for address generation")]
    MaxSeedLengthExceeded,
    #[error("Provided seeds do not result in a valid address")]
    InvalidSeeds,
    #[error("Provided owner is not allowed")]
    IllegalOwner,
}
impl<T> DecodeError<T> for PubkeyError {
    fn type_of() -> &'static str {
        "PubkeyError"
    }
}
impl From<u64> for PubkeyError {
    fn from(error: u64) -> Self {
        match error {
            0 => PubkeyError::MaxSeedLengthExceeded,
            1 => PubkeyError::InvalidSeeds,
            _ => panic!("Unsupported PubkeyError"),
        }
    }
}

#[wasm_bindgen]
#[repr(transparent)]
#[derive(
    AbiExample,
    BorshDeserialize,
    BorshSchema,
    BorshSerialize,
    Clone,
    Copy,
    Default,
    Deserialize,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    Pod,
    Serialize,
    Zeroable,
)]
pub struct Pubkey(pub(crate) [u8; 32]);

impl crate::sanitize::Sanitize for Pubkey {}

#[derive(Error, Debug, Serialize, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum ParsePubkeyError {
    #[error("String is the wrong size")]
    WrongSize,
    #[error("Invalid Base58 string")]
    Invalid,
}

impl From<Infallible> for ParsePubkeyError {
    fn from(_: Infallible) -> Self {
        unreachable!("Infallible unihnabited");
    }
}

impl<T> DecodeError<T> for ParsePubkeyError {
    fn type_of() -> &'static str {
        "ParsePubkeyError"
    }
}

impl FromStr for Pubkey {
    type Err = ParsePubkeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_LEN {
            return Err(ParsePubkeyError::WrongSize);
        }
        let pubkey_vec = bs58::decode(s)
            .into_vec()
            .map_err(|_| ParsePubkeyError::Invalid)?;
        if pubkey_vec.len() != mem::size_of::<Pubkey>() {
            Err(ParsePubkeyError::WrongSize)
        } else {
            Ok(Pubkey::new(&pubkey_vec))
        }
    }
}

impl TryFrom<&str> for Pubkey {
    type Error = ParsePubkeyError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Pubkey::from_str(s)
    }
}

pub fn bytes_are_curve_point<T: AsRef<[u8]>>(_bytes: T) -> bool {
    #[cfg(not(target_arch = "bpf"))]
    {
        curve25519_dalek::edwards::CompressedEdwardsY::from_slice(_bytes.as_ref())
            .decompress()
            .is_some()
    }
    #[cfg(target_arch = "bpf")]
    unimplemented!();
}

impl Pubkey {
    pub fn new(pubkey_vec: &[u8]) -> Self {
        Self(
            <[u8; 32]>::try_from(<&[u8]>::clone(&pubkey_vec))
                .expect("Slice must be the same length as a Pubkey"),
        )
    }

    pub const fn new_from_array(pubkey_array: [u8; 32]) -> Self {
        Self(pubkey_array)
    }

    #[deprecated(since = "1.3.9", note = "Please use 'Pubkey::new_unique' instead")]
    #[cfg(not(target_arch = "bpf"))]
    pub fn new_rand() -> Self {
        // Consider removing Pubkey::new_rand() entirely in the v1.5 or v1.6 timeframe
        Pubkey::new(&rand::random::<[u8; 32]>())
    }

    /// unique Pubkey for tests and benchmarks.
    pub fn new_unique() -> Self {
        use crate::atomic_u64::AtomicU64;
        static I: AtomicU64 = AtomicU64::new(1);

        let mut b = [0u8; 32];
        let i = I.fetch_add(1);
        b[0..8].copy_from_slice(&i.to_le_bytes());
        Self::new(&b)
    }

    pub fn create_with_seed(
        base: &Pubkey,
        seed: &str,
        owner: &Pubkey,
    ) -> Result<Pubkey, PubkeyError> {
        if seed.len() > MAX_SEED_LEN {
            return Err(PubkeyError::MaxSeedLengthExceeded);
        }

        let owner = owner.as_ref();
        if owner.len() >= PDA_MARKER.len() {
            let slice = &owner[owner.len() - PDA_MARKER.len()..];
            if slice == PDA_MARKER {
                return Err(PubkeyError::IllegalOwner);
            }
        }

        Ok(Pubkey::new(
            hashv(&[base.as_ref(), seed.as_ref(), owner]).as_ref(),
        ))
    }

    /// Find a valid [program derived address][pda] and its corresponding bump seed.
    ///
    /// [pda]: https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses
    ///
    /// Program derived addresses (PDAs) are account keys that only the program,
    /// `program_id`, has the authority to sign. The address is of the same form
    /// as a Solana `Pubkey`, except they are ensured to not be on the ed25519
    /// curve and thus have no associated private key. When performing
    /// cross-program invocations the program can "sign" for the key by calling
    /// [`invoke_signed`] and passing the same seeds used to generate the
    /// address, along with the calculated _bump seed_, which this function
    /// returns as the second tuple element. The runtime will verify that the
    /// program associated with this address is the caller and thus authorized
    /// to be the signer.
    ///
    /// [`invoke_signed`]: crate::program::invoke_signed
    ///
    /// The `seeds` are application-specific, and must be carefully selected to
    /// uniquely derive accounts per application requirements. It is common to
    /// use static strings and other pubkeys as seeds.
    ///
    /// Because the program address must not lie on the ed25519 curve, there may
    /// be seed and program id combinations that are invalid. For this reason,
    /// an extra seed (the bump seed) is calculated that results in a
    /// point off the curve. The bump seed must be passed as an additional seed
    /// when calling `invoke_signed`.
    ///
    /// The processes of finding a valid program address is by trial and error,
    /// and even though it is deterministic given a set of inputs it can take a
    /// variable amount of time to succeed across different inputs.  This means
    /// that when called from an on-chain program it may incur a variable amount
    /// of the program's compute budget.  Programs that are meant to be very
    /// performant may not want to use this function because it could take a
    /// considerable amount of time. Programs that are already at risk
    /// of exceeding their compute budget should call this with care since
    /// there is a chance that the program's budget may be occasionally
    /// and unpredictably exceeded.
    ///
    /// As all account addresses accessed by an on-chain Solana program must be
    /// explicitly passed to the program, it is typical for the PDAs to be
    /// derived in off-chain client programs, avoiding the compute cost of
    /// generating the address on-chain. The address may or may not then be
    /// verified by re-deriving it on-chain, depending on the requirements of
    /// the program. This verification may be performed without the overhead of
    /// re-searching for the bump key by using the [`create_program_address`]
    /// function.
    ///
    /// [`create_program_address`]: Pubkey::create_program_address
    ///
    /// **Warning**: Because of the way the seeds are hashed there is a potential
    /// for program address collisions for the same program id.  The seeds are
    /// hashed sequentially which means that seeds {"abcdef"}, {"abc", "def"},
    /// and {"ab", "cd", "ef"} will all result in the same program address given
    /// the same program id. Since the chance of collision is local to a given
    /// program id, the developer of that program must take care to choose seeds
    /// that do not collide with each other. For seed schemes that are susceptible
    /// to this type of hash collision, a common remedy is to insert separators
    /// between seeds, e.g. transforming {"abc", "def"} into {"abc", "-", "def"}.
    ///
    /// # Panics
    ///
    /// Panics in the statistically improbable event that a bump seed could not be
    /// found. Use [`try_find_program_address`] to handle this case.
    ///
    /// [`try_find_program_address`]: Pubkey::try_find_program_address
    ///
    /// Panics if any of the following are true:
    ///
    /// - the number of provided seeds is greater than, _or equal to_,  [`MAX_SEEDS`],
    /// - any individual seed's length is greater than [`MAX_SEED_LEN`].
    ///
    /// # Examples
    ///
    /// This example illustrates a simple case of creating a "vault" account
    /// which is derived from the payer account, but owned by an on-chain
    /// program. The program derived address is derived in an off-chain client
    /// program, which invokes an on-chain Solana program that uses the address
    /// to create a new account owned and controlled by the program itself.
    ///
    /// By convention, the on-chain program will be compiled for use in two
    /// different contexts: both on-chain, to interpret a custom program
    /// instruction as a Solana transaction; and off-chain, as a library, so
    /// that clients can share the instruction data structure, constructors, and
    /// other common code.
    ///
    /// First the on-chain Solana program:
    ///
    /// ```
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// # use sino_program::{
    /// #     pubkey::Pubkey,
    /// #     entrypoint::ProgramResult,
    /// #     program::invoke_signed,
    /// #     system_instruction,
    /// #     account_info::{
    /// #         AccountInfo,
    /// #         next_account_info,
    /// #     },
    /// # };
    /// // The custom instruction processed by our program. It includes the
    /// // PDA's bump seed, which is derived by the client program. This
    /// // definition is also imported into the off-chain client program.
    /// // The computed address of the PDA will be passed to this program via
    /// // the `accounts` vector of the `Instruction` type.
    /// #[derive(BorshSerialize, BorshDeserialize, Debug)]
    /// pub struct InstructionData {
    ///     pub vault_bump_seed: u8,
    ///     pub wens: u64,
    /// }
    ///
    /// // The size in bytes of a vault account. The client program needs
    /// // this information to calculate the quantity of wens necessary
    /// // to pay for the account's rent.
    /// pub static VAULT_ACCOUNT_SIZE: u64 = 1024;
    ///
    /// // The entrypoint of the on-chain program, as provided to the
    /// // `entrypoint!` macro.
    /// fn process_instruction(
    ///     program_id: &Pubkey,
    ///     accounts: &[AccountInfo],
    ///     instruction_data: &[u8],
    /// ) -> ProgramResult {
    ///     let account_info_iter = &mut accounts.iter();
    ///     let payer = next_account_info(account_info_iter)?;
    ///     // The vault PDA, derived from the payer's address
    ///     let vault = next_account_info(account_info_iter)?;
    ///
    ///     let mut instruction_data = instruction_data;
    ///     let instr = InstructionData::deserialize(&mut instruction_data)?;
    ///     let vault_bump_seed = instr.vault_bump_seed;
    ///     let wens = instr.wens;
    ///     let vault_size = VAULT_ACCOUNT_SIZE;
    ///
    ///     // Invoke the system program to create an account while virtually
    ///     // signing with the vault PDA, which is owned by this caller program.
    ///     invoke_signed(
    ///         &system_instruction::create_account(
    ///             &payer.key,
    ///             &vault.key,
    ///             wens,
    ///             vault_size,
    ///             &program_id,
    ///         ),
    ///         &[
    ///             payer.clone(),
    ///             vault.clone(),
    ///         ],
    ///         // A slice of seed slices, each seed slice being the set
    ///         // of seeds used to generate one of the PDAs required by the
    ///         // callee program, the final seed being a single-element slice
    ///         // containing the `u8` bump seed.
    ///         &[
    ///             &[
    ///                 b"vault",
    ///                 payer.key.as_ref(),
    ///                 &[vault_bump_seed],
    ///             ],
    ///         ]
    ///     )?;
    ///
    ///     Ok(())
    /// }
    /// ```
    ///
    /// The client program:
    ///
    /// ```ignore
    /// # // NB: This example depends on sdk and solana_client, and adding
    /// # // those as dev-dependencies would create an unpublishable circular
    /// # // dependency, hence it is ignored.
    /// #
    /// # use borsh::{BorshSerialize, BorshDeserialize};
    /// # use sino_program::pubkey::Pubkey;
    /// # use sino_program::instruction::Instruction;
    /// # use sino_program::hash::Hash;
    /// # use sino_program::instruction::AccountMeta;
    /// # use sino_program::system_program;
    /// # use sdk::signature::Keypair;
    /// # use sdk::signature::{Signer, Signature};
    /// # use sdk::transaction::Transaction;
    /// # use solana_client::rpc_client::RpcClient;
    /// # use std::convert::TryFrom;
    /// #
    /// # #[derive(BorshSerialize, BorshDeserialize, Debug)]
    /// # struct InstructionData {
    /// #    pub vault_bump_seed: u8,
    /// #    pub wens: u64,
    /// # }
    /// #
    /// # pub static VAULT_ACCOUNT_SIZE: u64 = 1024;
    /// # let program_id = Pubkey::new_unique();
    /// # let payer = Keypair::new();
    /// # let rpc_client = RpcClient::new("no-run".to_string());
    /// #
    /// // Derive the PDA from the payer account, a string representing the unique
    /// // purpose of the account ("vault"), and the address of our on-chain program.
    /// let (vault_pubkey, vault_bump_seed) = Pubkey::find_program_address(
    ///     &[b"vault", payer.pubkey().as_ref()],
    ///     &program_id
    /// );
    ///
    /// // Get the amount of wens needed to pay for the vault's rent
    /// let vault_account_size = usize::try_from(VAULT_ACCOUNT_SIZE)?;
    /// let wens = rpc_client.get_minimum_balance_for_rent_exemption(vault_account_size)?;
    ///
    /// // The on-chain program's instruction data, imported from that program's crate.
    /// let instr_data = InstructionData {
    ///     vault_bump_seed,
    ///     wens,
    /// };
    ///
    /// // The accounts required by both our on-chain program and the system program's
    /// // `create_account` instruction, including the vault's address.
    /// let accounts = vec![
    ///     AccountMeta::new(payer.pubkey(), true),
    ///     AccountMeta::new(vault_pubkey, false),
    ///     AccountMeta::new(system_program::ID, false),
    /// ];
    ///
    /// // Create the instruction by serializing our instruction data via borsh
    /// let instruction = Instruction::new_with_borsh(
    ///     program_id,
    ///     &instr_data,
    ///     accounts,
    /// );
    ///
    /// let blockhash = rpc_client.get_latest_blockhash()?;
    ///
    /// let transaction = Transaction::new_signed_with_payer(
    ///     &[instruction],
    ///     Some(&payer.pubkey()),
    ///     &[&payer],
    ///     blockhash,
    /// );
    ///
    /// rpc_client.send_and_confirm_transaction(&transaction)?;
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
        Self::try_find_program_address(seeds, program_id)
            .unwrap_or_else(|| panic!("Unable to find a viable program address bump seed"))
    }

    /// Find a valid [program derived address][pda] and its corresponding bump seed.
    ///
    /// [pda]: https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses
    ///
    /// The only difference between this method and [`find_program_address`]
    /// is that this one returns `None` in the statistically improbable event
    /// that a bump seed cannot be found; or if any of `find_program_address`'s
    /// preconditions are violated.
    ///
    /// See the documentation for [`find_program_address`] for a full description.
    ///
    /// [`find_program_address`]: Pubkey::find_program_address
    #[allow(clippy::same_item_push)]
    pub fn try_find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> Option<(Pubkey, u8)> {
        // Perform the calculation inline, calling this from within a program is
        // not supported
        #[cfg(not(target_arch = "bpf"))]
        {
            let mut bump_seed = [std::u8::MAX];
            for _ in 0..std::u8::MAX {
                {
                    let mut seeds_with_bump = seeds.to_vec();
                    seeds_with_bump.push(&bump_seed);
                    match Self::create_program_address(&seeds_with_bump, program_id) {
                        Ok(address) => return Some((address, bump_seed[0])),
                        Err(PubkeyError::InvalidSeeds) => (),
                        _ => break,
                    }
                }
                bump_seed[0] -= 1;
            }
            None
        }
        // Call via a system call to perform the calculation
        #[cfg(target_arch = "bpf")]
        {
            extern "C" {
                fn sor_try_find_program_address(
                    seeds_addr: *const u8,
                    seeds_len: u64,
                    program_id_addr: *const u8,
                    address_bytes_addr: *const u8,
                    bump_seed_addr: *const u8,
                ) -> u64;
            }
            let mut bytes = [0; 32];
            let mut bump_seed = std::u8::MAX;
            let result = unsafe {
                sor_try_find_program_address(
                    seeds as *const _ as *const u8,
                    seeds.len() as u64,
                    program_id as *const _ as *const u8,
                    &mut bytes as *mut _ as *mut u8,
                    &mut bump_seed as *mut _ as *mut u8,
                )
            };
            match result {
                crate::entrypoint::SUCCESS => Some((Pubkey::new(&bytes), bump_seed)),
                _ => None,
            }
        }
    }

    /// Create a valid [program derived address][pda] without searching for a bump seed.
    ///
    /// [pda]: https://docs.solana.com/developing/programming-model/calling-between-programs#program-derived-addresses
    ///
    /// Because this function does not create a bump seed, it may unpredictably
    /// return an error for any given set of seeds and is not generally suitable
    /// for creating program derived addresses.
    ///
    /// However, it can be used for efficiently verifying that a set of seeds plus
    /// bump seed generated by [`find_program_address`] derives a particular
    /// address as expected. See the example for details.
    ///
    /// See the documentation for [`find_program_address`] for a full description
    /// of program derived addresses and bump seeds.
    ///
    /// [`find_program_address`]: Pubkey::find_program_address
    ///
    /// # Examples
    ///
    /// Creating a program derived address involves iteratively searching for a
    /// bump seed for which the derived [`Pubkey`] does not lie on the ed25519
    /// curve. This search process is generally performed off-chain, with the
    /// [`find_program_address`] function, after which the client passes the
    /// bump seed to the program as instruction data.
    ///
    /// Depending on the application requirements, a program may wish to verify
    /// that the set of seeds, plus the bump seed, do correctly generate an
    /// expected address.
    ///
    /// The verification is performed by appending to the other seeds one
    /// additional seed slice that contains the single `u8` bump seed, calling
    /// `create_program_address`, checking that the return value is `Ok`, and
    /// that the returned `Pubkey` has the expected value.
    ///
    /// ```
    /// # use sino_program::pubkey::Pubkey;
    /// # let program_id = Pubkey::new_unique();
    /// let (expected_pda, bump_seed) = Pubkey::find_program_address(&[b"vault"], &program_id);
    /// let actual_pda = Pubkey::create_program_address(&[b"vault", &[bump_seed]], &program_id)?;
    /// assert_eq!(expected_pda, actual_pda);
    /// # Ok::<(), anyhow::Error>(())
    /// ```
    pub fn create_program_address(
        seeds: &[&[u8]],
        program_id: &Pubkey,
    ) -> Result<Pubkey, PubkeyError> {
        if seeds.len() > MAX_SEEDS {
            return Err(PubkeyError::MaxSeedLengthExceeded);
        }
        for seed in seeds.iter() {
            if seed.len() > MAX_SEED_LEN {
                return Err(PubkeyError::MaxSeedLengthExceeded);
            }
        }

        // Perform the calculation inline, calling this from within a program is
        // not supported
        #[cfg(not(target_arch = "bpf"))]
        {
            let mut hasher = crate::hash::Hasher::default();
            for seed in seeds.iter() {
                hasher.hash(seed);
            }
            hasher.hashv(&[program_id.as_ref(), PDA_MARKER]);
            let hash = hasher.result();

            if bytes_are_curve_point(hash) {
                return Err(PubkeyError::InvalidSeeds);
            }

            Ok(Pubkey::new(hash.as_ref()))
        }
        // Call via a system call to perform the calculation
        #[cfg(target_arch = "bpf")]
        {
            extern "C" {
                fn sor_create_program_address(
                    seeds_addr: *const u8,
                    seeds_len: u64,
                    program_id_addr: *const u8,
                    address_bytes_addr: *const u8,
                ) -> u64;
            }
            let mut bytes = [0; 32];
            let result = unsafe {
                sor_create_program_address(
                    seeds as *const _ as *const u8,
                    seeds.len() as u64,
                    program_id as *const _ as *const u8,
                    &mut bytes as *mut _ as *mut u8,
                )
            };
            match result {
                crate::entrypoint::SUCCESS => Ok(Pubkey::new(&bytes)),
                _ => Err(result.into()),
            }
        }
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn is_on_curve(&self) -> bool {
        bytes_are_curve_point(self)
    }

    /// Log a `Pubkey` from a program
    pub fn log(&self) {
        #[cfg(target_arch = "bpf")]
        {
            extern "C" {
                fn sor_log_pubkey(pubkey_addr: *const u8);
            }
            unsafe { sor_log_pubkey(self.as_ref() as *const _ as *const u8) };
        }

        #[cfg(not(target_arch = "bpf"))]
        crate::program_stubs::sor_log(&self.to_string());
    }
}

impl AsRef<[u8]> for Pubkey {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl AsMut<[u8]> for Pubkey {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0[..]
    }
}

impl fmt::Debug for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl fmt::Display for Pubkey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

#[cfg(test)]
mod tests {
    use {super::*, std::str::from_utf8};

    #[test]
    fn test_new_unique() {
        assert!(Pubkey::new_unique() != Pubkey::new_unique());
    }

    #[test]
    fn pubkey_fromstr() {
        let pubkey = Pubkey::new_unique();
        let mut pubkey_base58_str = bs58::encode(pubkey.0).into_string();

        assert_eq!(pubkey_base58_str.parse::<Pubkey>(), Ok(pubkey));

        pubkey_base58_str.push_str(&bs58::encode(pubkey.0).into_string());
        assert_eq!(
            pubkey_base58_str.parse::<Pubkey>(),
            Err(ParsePubkeyError::WrongSize)
        );

        pubkey_base58_str.truncate(pubkey_base58_str.len() / 2);
        assert_eq!(pubkey_base58_str.parse::<Pubkey>(), Ok(pubkey));

        pubkey_base58_str.truncate(pubkey_base58_str.len() / 2);
        assert_eq!(
            pubkey_base58_str.parse::<Pubkey>(),
            Err(ParsePubkeyError::WrongSize)
        );

        let mut pubkey_base58_str = bs58::encode(pubkey.0).into_string();
        assert_eq!(pubkey_base58_str.parse::<Pubkey>(), Ok(pubkey));

        // throw some non-base58 stuff in there
        pubkey_base58_str.replace_range(..1, "I");
        assert_eq!(
            pubkey_base58_str.parse::<Pubkey>(),
            Err(ParsePubkeyError::Invalid)
        );

        // too long input string
        // longest valid encoding
        let mut too_long = bs58::encode(&[255u8; PUBKEY_BYTES]).into_string();
        // and one to grow on
        too_long.push('1');
        assert_eq!(too_long.parse::<Pubkey>(), Err(ParsePubkeyError::WrongSize));
    }

    #[test]
    fn test_create_with_seed() {
        assert!(
            Pubkey::create_with_seed(&Pubkey::new_unique(), "☉", &Pubkey::new_unique()).is_ok()
        );
        assert_eq!(
            Pubkey::create_with_seed(
                &Pubkey::new_unique(),
                from_utf8(&[127; MAX_SEED_LEN + 1]).unwrap(),
                &Pubkey::new_unique()
            ),
            Err(PubkeyError::MaxSeedLengthExceeded)
        );
        assert!(Pubkey::create_with_seed(
            &Pubkey::new_unique(),
            "\
             \u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\
             ",
            &Pubkey::new_unique()
        )
        .is_ok());
        // utf-8 abuse ;)
        assert_eq!(
            Pubkey::create_with_seed(
                &Pubkey::new_unique(),
                "\
                 x\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\u{10FFFF}\
                 ",
                &Pubkey::new_unique()
            ),
            Err(PubkeyError::MaxSeedLengthExceeded)
        );

        assert!(Pubkey::create_with_seed(
            &Pubkey::new_unique(),
            std::str::from_utf8(&[0; MAX_SEED_LEN]).unwrap(),
            &Pubkey::new_unique(),
        )
        .is_ok());

        assert!(
            Pubkey::create_with_seed(&Pubkey::new_unique(), "", &Pubkey::new_unique(),).is_ok()
        );

        assert_eq!(
            Pubkey::create_with_seed(
                &Pubkey::default(),
                "limber chicken: 4/45",
                &Pubkey::default(),
            ),
            Ok("9h1HyLCW5dZnBVap8C5egQ9Z6pHyjsh5MNy83iPqqRuq"
                .parse()
                .unwrap())
        );
    }

    #[test]
    fn test_create_program_address() {
        let exceeded_seed = &[127; MAX_SEED_LEN + 1];
        let max_seed = &[0; MAX_SEED_LEN];
        let exceeded_seeds: &[&[u8]] = &[
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[8],
            &[9],
            &[10],
            &[11],
            &[12],
            &[13],
            &[14],
            &[15],
            &[16],
            &[17],
        ];
        let max_seeds: &[&[u8]] = &[
            &[1],
            &[2],
            &[3],
            &[4],
            &[5],
            &[6],
            &[7],
            &[8],
            &[9],
            &[10],
            &[11],
            &[12],
            &[13],
            &[14],
            &[15],
            &[16],
        ];
        let program_id = Pubkey::from_str("BPFLoaderUpgradeab1e11111111111111111111111").unwrap();
        let public_key = Pubkey::from_str("SeedPubey1111111111111111111111111111111111").unwrap();

        assert_eq!(
            Pubkey::create_program_address(&[exceeded_seed], &program_id),
            Err(PubkeyError::MaxSeedLengthExceeded)
        );
        assert_eq!(
            Pubkey::create_program_address(&[b"short_seed", exceeded_seed], &program_id),
            Err(PubkeyError::MaxSeedLengthExceeded)
        );
        assert!(Pubkey::create_program_address(&[max_seed], &program_id).is_ok());
        assert_eq!(
            Pubkey::create_program_address(exceeded_seeds, &program_id),
            Err(PubkeyError::MaxSeedLengthExceeded)
        );
        assert!(Pubkey::create_program_address(max_seeds, &program_id).is_ok());
        assert_eq!(
            Pubkey::create_program_address(&[b"", &[1]], &program_id),
            Ok("BwqrghZA2htAcqq8dzP1WDAhTXYTYWj7CHxF5j7TDBAe"
                .parse()
                .unwrap())
        );
        assert_eq!(
            Pubkey::create_program_address(&["☉".as_ref(), &[0]], &program_id),
            Ok("13yWmRpaTR4r5nAktwLqMpRNr28tnVUZw26rTvPSSB19"
                .parse()
                .unwrap())
        );
        assert_eq!(
            Pubkey::create_program_address(&[b"Talking", b"Squirrels"], &program_id),
            Ok("2fnQrngrQT4SeLcdToJAD96phoEjNL2man2kfRLCASVk"
                .parse()
                .unwrap())
        );
        assert_eq!(
            Pubkey::create_program_address(&[public_key.as_ref(), &[1]], &program_id),
            Ok("976ymqVnfE32QFe6NfGDctSvVa36LWnvYxhU6G2232YL"
                .parse()
                .unwrap())
        );
        assert_ne!(
            Pubkey::create_program_address(&[b"Talking", b"Squirrels"], &program_id).unwrap(),
            Pubkey::create_program_address(&[b"Talking"], &program_id).unwrap(),
        );
    }

    #[test]
    fn test_pubkey_off_curve() {
        // try a bunch of random input, all successful generated program
        // addresses must land off the curve and be unique
        let mut addresses = vec![];
        for _ in 0..1_000 {
            let program_id = Pubkey::new_unique();
            let bytes1 = rand::random::<[u8; 10]>();
            let bytes2 = rand::random::<[u8; 32]>();
            if let Ok(program_address) =
                Pubkey::create_program_address(&[&bytes1, &bytes2], &program_id)
            {
                let is_on_curve = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(
                    &program_address.to_bytes(),
                )
                .decompress()
                .is_some();
                assert!(!is_on_curve);
                assert!(!addresses.contains(&program_address));
                addresses.push(program_address);
            }
        }
    }

    #[test]
    fn test_find_program_address() {
        for _ in 0..1_000 {
            let program_id = Pubkey::new_unique();
            let (address, bump_seed) =
                Pubkey::find_program_address(&[b"Lil'", b"Bits"], &program_id);
            assert_eq!(
                address,
                Pubkey::create_program_address(&[b"Lil'", b"Bits", &[bump_seed]], &program_id)
                    .unwrap()
            );
        }
    }

    fn pubkey_from_seed_by_marker(marker: &[u8]) -> Result<Pubkey, PubkeyError> {
        let key = Pubkey::new_unique();
        let owner = Pubkey::default();

        let mut to_fake = owner.to_bytes().to_vec();
        to_fake.extend_from_slice(marker);

        let seed = &String::from_utf8(to_fake[..to_fake.len() - 32].to_vec()).expect("not utf8");
        let base = &Pubkey::try_from_slice(&to_fake[to_fake.len() - 32..]).unwrap();

        Pubkey::create_with_seed(&key, seed, base)
    }

    #[test]
    fn test_create_with_seed_rejects_illegal_owner() {
        assert_eq!(
            pubkey_from_seed_by_marker(PDA_MARKER),
            Err(PubkeyError::IllegalOwner)
        );
        assert!(pubkey_from_seed_by_marker(&PDA_MARKER[1..]).is_ok());
    }
}
