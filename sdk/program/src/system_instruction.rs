#[allow(deprecated)]
use {
    crate::{
        decode_error::DecodeError,
        instruction::{AccountMeta, Instruction, InstructionError},
        nonce,
        pubkey::Pubkey,
        system_program,
        sysvar::{recent_blockhashes, rent},
    },
    num_derive::{FromPrimitive, ToPrimitive},
    thiserror::Error,
};

#[derive(Error, Debug, Serialize, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum SystemError {
    #[error("an account with the same address already exists")]
    AccountAlreadyInUse,
    #[error("account does not have enough SOR to perform the operation")]
    ResultWithNegativeWens,
    #[error("cannot assign account to this program id")]
    InvalidProgramId,
    #[error("cannot allocate account data of this length")]
    InvalidAccountDataLength,
    #[error("length of requested seed is too long")]
    MaxSeedLengthExceeded,
    #[error("provided address does not match addressed derived from seed")]
    AddressWithSeedMismatch,
    #[error("advancing stored nonce requires a populated RecentBlockhashes sysvar")]
    NonceNoRecentBlockhashes,
    #[error("stored nonce is still in recent_blockhashes")]
    NonceBlockhashNotExpired,
    #[error("specified nonce does not match stored nonce")]
    NonceUnexpectedBlockhashValue,
}

impl<T> DecodeError<T> for SystemError {
    fn type_of() -> &'static str {
        "SystemError"
    }
}

#[derive(Error, Debug, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum NonceError {
    #[error("recent blockhash list is empty")]
    NoRecentBlockhashes,
    #[error("stored nonce is still in recent_blockhashes")]
    NotExpired,
    #[error("specified nonce does not match stored nonce")]
    UnexpectedValue,
    #[error("cannot handle request in current account state")]
    BadAccountState,
}

impl<E> DecodeError<E> for NonceError {
    fn type_of() -> &'static str {
        "NonceError"
    }
}

#[derive(Error, Debug, Clone, PartialEq, FromPrimitive, ToPrimitive)]
enum NonceErrorAdapter {
    #[error("recent blockhash list is empty")]
    NoRecentBlockhashes,
    #[error("stored nonce is still in recent_blockhashes")]
    NotExpired,
    #[error("specified nonce does not match stored nonce")]
    UnexpectedValue,
    #[error("cannot handle request in current account state")]
    BadAccountState,
}

impl<E> DecodeError<E> for NonceErrorAdapter {
    fn type_of() -> &'static str {
        "NonceErrorAdapter"
    }
}

impl From<NonceErrorAdapter> for NonceError {
    fn from(e: NonceErrorAdapter) -> Self {
        match e {
            NonceErrorAdapter::NoRecentBlockhashes => NonceError::NoRecentBlockhashes,
            NonceErrorAdapter::NotExpired => NonceError::NotExpired,
            NonceErrorAdapter::UnexpectedValue => NonceError::UnexpectedValue,
            NonceErrorAdapter::BadAccountState => NonceError::BadAccountState,
        }
    }
}

pub fn nonce_to_instruction_error(error: NonceError, use_system_variant: bool) -> InstructionError {
    if use_system_variant {
        match error {
            NonceError::NoRecentBlockhashes => SystemError::NonceNoRecentBlockhashes.into(),
            NonceError::NotExpired => SystemError::NonceBlockhashNotExpired.into(),
            NonceError::UnexpectedValue => SystemError::NonceUnexpectedBlockhashValue.into(),
            NonceError::BadAccountState => InstructionError::InvalidAccountData,
        }
    } else {
        match error {
            NonceError::NoRecentBlockhashes => NonceErrorAdapter::NoRecentBlockhashes.into(),
            NonceError::NotExpired => NonceErrorAdapter::NotExpired.into(),
            NonceError::UnexpectedValue => NonceErrorAdapter::UnexpectedValue.into(),
            NonceError::BadAccountState => NonceErrorAdapter::BadAccountState.into(),
        }
    }
}

pub fn instruction_to_nonce_error(
    error: &InstructionError,
    use_system_variant: bool,
) -> Option<NonceError> {
    if use_system_variant {
        match error {
            InstructionError::Custom(discriminant) => {
                match SystemError::decode_custom_error_to_enum(*discriminant) {
                    Some(SystemError::NonceNoRecentBlockhashes) => {
                        Some(NonceError::NoRecentBlockhashes)
                    }
                    Some(SystemError::NonceBlockhashNotExpired) => Some(NonceError::NotExpired),
                    Some(SystemError::NonceUnexpectedBlockhashValue) => {
                        Some(NonceError::UnexpectedValue)
                    }
                    _ => None,
                }
            }
            InstructionError::InvalidAccountData => Some(NonceError::BadAccountState),
            _ => None,
        }
    } else if let InstructionError::Custom(discriminant) = error {
        let maybe: Option<NonceErrorAdapter> =
            NonceErrorAdapter::decode_custom_error_to_enum(*discriminant);
        maybe.map(NonceError::from)
    } else {
        None
    }
}

/// maximum permitted size of data: 10 MB
pub const MAX_PERMITTED_DATA_LENGTH: u64 = 10 * 1024 * 1024;

#[frozen_abi(digest = "5e22s2kFu9Do77hdcCyxyhuKHD8ThAB6Q6dNaLTCjL5M")]
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, AbiExample, AbiEnumVisitor)]
pub enum SystemInstruction {
    /// Create a new account
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE, SIGNER]` New account
    CreateAccount {
        /// Number of wens to transfer to the new account
        wens: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Address of program that will own the new account
        owner: Pubkey,
    },

    /// Assign account to a program
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Assigned account public key
    Assign {
        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer wens
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Recipient account
    Transfer { wens: u64 },

    /// Create a new account at an address derived from a base pubkey and a seed
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` Funding account
    ///   1. `[WRITE]` Created account
    ///   2. `[SIGNER]` (optional) Base account; the account matching the base Pubkey below must be
    ///                          provided as a signer, but may be the same as the funding account
    ///                          and provided as account 0
    CreateAccountWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `Pubkey::MAX_SEED_LEN`
        seed: String,

        /// Number of wens to transfer to the new account
        wens: u64,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account address
        owner: Pubkey,
    },

    /// Consumes a stored nonce, replacing it with a successor
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[SIGNER]` Nonce authority
    AdvanceNonceAccount,

    /// Withdraw funds from a nonce account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[WRITE]` Recipient account
    ///   2. `[]` RecentBlockhashes sysvar
    ///   3. `[]` Rent sysvar
    ///   4. `[SIGNER]` Nonce authority
    ///
    /// The `u64` parameter is the wens to withdraw, which must leave the
    /// account balance above the rent exempt reserve or at zero.
    WithdrawNonceAccount(u64),

    /// Drive state of Uninitialized nonce account to Initialized, setting the nonce value
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[]` RecentBlockhashes sysvar
    ///   2. `[]` Rent sysvar
    ///
    /// The `Pubkey` parameter specifies the entity authorized to execute nonce
    /// instruction on the account
    ///
    /// No signatures are required to execute this instruction, enabling derived
    /// nonce account addresses
    InitializeNonceAccount(Pubkey),

    /// Change the entity authorized to execute nonce instructions on the account
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    ///   1. `[SIGNER]` Nonce authority
    ///
    /// The `Pubkey` parameter identifies the entity to authorize
    AuthorizeNonceAccount(Pubkey),

    /// Allocate space in a (possibly new) account without funding
    ///
    /// # Account references
    ///   0. `[WRITE, SIGNER]` New account
    Allocate {
        /// Number of bytes of memory to allocate
        space: u64,
    },

    /// Allocate space for and assign an account at an address
    ///    derived from a base public key and a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Allocated account
    ///   1. `[SIGNER]` Base account
    AllocateWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: String,

        /// Number of bytes of memory to allocate
        space: u64,

        /// Owner program account
        owner: Pubkey,
    },

    /// Assign account to a program based on a seed
    ///
    /// # Account references
    ///   0. `[WRITE]` Assigned account
    ///   1. `[SIGNER]` Base account
    AssignWithSeed {
        /// Base public key
        base: Pubkey,

        /// String of ASCII chars, no longer than `pubkey::MAX_SEED_LEN`
        seed: String,

        /// Owner program account
        owner: Pubkey,
    },

    /// Transfer wens from a derived address
    ///
    /// # Account references
    ///   0. `[WRITE]` Funding account
    ///   1. `[SIGNER]` Base for funding account
    ///   2. `[WRITE]` Recipient account
    TransferWithSeed {
        /// Amount to transfer
        wens: u64,

        /// Seed to use to derive the funding account address
        from_seed: String,

        /// Owner to use to derive the funding account address
        from_owner: Pubkey,
    },

    /// One-time idempotent upgrade of legacy nonce versions in order to bump
    /// them out of chain blockhash domain.
    ///
    /// # Account references
    ///   0. `[WRITE]` Nonce account
    UpgradeNonceAccount,
}

pub fn create_account(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    wens: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, true),
        AccountMeta::new(*to_pubkey, true),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::CreateAccount {
            wens,
            space,
            owner: *owner,
        },
        account_metas,
    )
}

// we accept `to` as a parameter so that callers do their own error handling when
//   calling create_with_seed()
pub fn create_account_with_seed(
    from_pubkey: &Pubkey,
    to_pubkey: &Pubkey, // must match create_with_seed(base, seed, owner)
    base: &Pubkey,
    seed: &str,
    wens: u64,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, true),
        AccountMeta::new(*to_pubkey, false),
        AccountMeta::new_readonly(*base, true),
    ];

    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::CreateAccountWithSeed {
            base: *base,
            seed: seed.to_string(),
            wens,
            space,
            owner: *owner,
        },
        account_metas,
    )
}

pub fn assign(pubkey: &Pubkey, owner: &Pubkey) -> Instruction {
    let account_metas = vec![AccountMeta::new(*pubkey, true)];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::Assign { owner: *owner },
        account_metas,
    )
}

pub fn assign_with_seed(
    address: &Pubkey, // must match create_with_seed(base, seed, owner)
    base: &Pubkey,
    seed: &str,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*address, false),
        AccountMeta::new_readonly(*base, true),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::AssignWithSeed {
            base: *base,
            seed: seed.to_string(),
            owner: *owner,
        },
        account_metas,
    )
}

pub fn transfer(from_pubkey: &Pubkey, to_pubkey: &Pubkey, wens: u64) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, true),
        AccountMeta::new(*to_pubkey, false),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::Transfer { wens },
        account_metas,
    )
}

pub fn transfer_with_seed(
    from_pubkey: &Pubkey, // must match create_with_seed(base, seed, owner)
    from_base: &Pubkey,
    from_seed: String,
    from_owner: &Pubkey,
    to_pubkey: &Pubkey,
    wens: u64,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*from_pubkey, false),
        AccountMeta::new_readonly(*from_base, true),
        AccountMeta::new(*to_pubkey, false),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::TransferWithSeed {
            wens,
            from_seed,
            from_owner: *from_owner,
        },
        account_metas,
    )
}

pub fn allocate(pubkey: &Pubkey, space: u64) -> Instruction {
    let account_metas = vec![AccountMeta::new(*pubkey, true)];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::Allocate { space },
        account_metas,
    )
}

pub fn allocate_with_seed(
    address: &Pubkey, // must match create_with_seed(base, seed, owner)
    base: &Pubkey,
    seed: &str,
    space: u64,
    owner: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*address, false),
        AccountMeta::new_readonly(*base, true),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::AllocateWithSeed {
            base: *base,
            seed: seed.to_string(),
            space,
            owner: *owner,
        },
        account_metas,
    )
}

/// Create and sign new SystemInstruction::Transfer transaction to many destinations
pub fn transfer_many(from_pubkey: &Pubkey, to_wens: &[(Pubkey, u64)]) -> Vec<Instruction> {
    to_wens
        .iter()
        .map(|(to_pubkey, wens)| transfer(from_pubkey, to_pubkey, *wens))
        .collect()
}

pub fn create_nonce_account_with_seed(
    from_pubkey: &Pubkey,
    nonce_pubkey: &Pubkey,
    base: &Pubkey,
    seed: &str,
    authority: &Pubkey,
    wens: u64,
) -> Vec<Instruction> {
    vec![
        create_account_with_seed(
            from_pubkey,
            nonce_pubkey,
            base,
            seed,
            wens,
            nonce::State::size() as u64,
            &system_program::id(),
        ),
        Instruction::new_with_bincode(
            system_program::id(),
            &SystemInstruction::InitializeNonceAccount(*authority),
            vec![
                AccountMeta::new(*nonce_pubkey, false),
                #[allow(deprecated)]
                AccountMeta::new_readonly(recent_blockhashes::id(), false),
                AccountMeta::new_readonly(rent::id(), false),
            ],
        ),
    ]
}

pub fn create_nonce_account(
    from_pubkey: &Pubkey,
    nonce_pubkey: &Pubkey,
    authority: &Pubkey,
    wens: u64,
) -> Vec<Instruction> {
    vec![
        create_account(
            from_pubkey,
            nonce_pubkey,
            wens,
            nonce::State::size() as u64,
            &system_program::id(),
        ),
        Instruction::new_with_bincode(
            system_program::id(),
            &SystemInstruction::InitializeNonceAccount(*authority),
            vec![
                AccountMeta::new(*nonce_pubkey, false),
                #[allow(deprecated)]
                AccountMeta::new_readonly(recent_blockhashes::id(), false),
                AccountMeta::new_readonly(rent::id(), false),
            ],
        ),
    ]
}

pub fn advance_nonce_account(nonce_pubkey: &Pubkey, authorized_pubkey: &Pubkey) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*nonce_pubkey, false),
        #[allow(deprecated)]
        AccountMeta::new_readonly(recent_blockhashes::id(), false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::AdvanceNonceAccount,
        account_metas,
    )
}

pub fn withdraw_nonce_account(
    nonce_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey,
    to_pubkey: &Pubkey,
    wens: u64,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*nonce_pubkey, false),
        AccountMeta::new(*to_pubkey, false),
        #[allow(deprecated)]
        AccountMeta::new_readonly(recent_blockhashes::id(), false),
        AccountMeta::new_readonly(rent::id(), false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::WithdrawNonceAccount(wens),
        account_metas,
    )
}

pub fn authorize_nonce_account(
    nonce_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey,
    new_authority: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*nonce_pubkey, false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
    ];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::AuthorizeNonceAccount(*new_authority),
        account_metas,
    )
}

/// One-time idempotent upgrade of legacy nonce versions in order to bump
/// them out of chain blockhash domain.
pub fn upgrade_nonce_account(nonce_pubkey: Pubkey) -> Instruction {
    let account_metas = vec![AccountMeta::new(nonce_pubkey, /*is_signer:*/ false)];
    Instruction::new_with_bincode(
        system_program::id(),
        &SystemInstruction::UpgradeNonceAccount,
        account_metas,
    )
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::instruction::{Instruction, InstructionError},
        num_traits::ToPrimitive,
    };

    fn get_keys(instruction: &Instruction) -> Vec<Pubkey> {
        instruction.accounts.iter().map(|x| x.pubkey).collect()
    }

    #[test]
    fn test_move_many() {
        let alice_pubkey = Pubkey::new_unique();
        let bob_pubkey = Pubkey::new_unique();
        let carol_pubkey = Pubkey::new_unique();
        let to_wens = vec![(bob_pubkey, 1), (carol_pubkey, 2)];

        let instructions = transfer_many(&alice_pubkey, &to_wens);
        assert_eq!(instructions.len(), 2);
        assert_eq!(get_keys(&instructions[0]), vec![alice_pubkey, bob_pubkey]);
        assert_eq!(get_keys(&instructions[1]), vec![alice_pubkey, carol_pubkey]);
    }

    #[test]
    fn test_create_nonce_account() {
        let from_pubkey = Pubkey::new_unique();
        let nonce_pubkey = Pubkey::new_unique();
        let authorized = nonce_pubkey;
        let ixs = create_nonce_account(&from_pubkey, &nonce_pubkey, &authorized, 42);
        assert_eq!(ixs.len(), 2);
        let ix = &ixs[0];
        assert_eq!(ix.program_id, system_program::id());
        let pubkeys: Vec<_> = ix.accounts.iter().map(|am| am.pubkey).collect();
        assert!(pubkeys.contains(&from_pubkey));
        assert!(pubkeys.contains(&nonce_pubkey));
    }

    #[test]
    fn test_nonce_error_decode() {
        use num_traits::FromPrimitive;
        fn pretty_err<T>(err: InstructionError) -> String
        where
            T: 'static + std::error::Error + DecodeError<T> + FromPrimitive,
        {
            if let InstructionError::Custom(code) = err {
                let specific_error: T = T::decode_custom_error_to_enum(code).unwrap();
                format!(
                    "{:?}: {}::{:?} - {}",
                    err,
                    T::type_of(),
                    specific_error,
                    specific_error,
                )
            } else {
                "".to_string()
            }
        }
        assert_eq!(
            "Custom(0): NonceError::NoRecentBlockhashes - recent blockhash list is empty",
            pretty_err::<NonceError>(NonceError::NoRecentBlockhashes.into())
        );
        assert_eq!(
            "Custom(1): NonceError::NotExpired - stored nonce is still in recent_blockhashes",
            pretty_err::<NonceError>(NonceError::NotExpired.into())
        );
        assert_eq!(
            "Custom(2): NonceError::UnexpectedValue - specified nonce does not match stored nonce",
            pretty_err::<NonceError>(NonceError::UnexpectedValue.into())
        );
        assert_eq!(
            "Custom(3): NonceError::BadAccountState - cannot handle request in current account state",
            pretty_err::<NonceError>(NonceError::BadAccountState.into())
        );
    }

    #[test]
    fn test_nonce_to_instruction_error() {
        assert_eq!(
            nonce_to_instruction_error(NonceError::NoRecentBlockhashes, false),
            NonceError::NoRecentBlockhashes.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::NotExpired, false),
            NonceError::NotExpired.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::UnexpectedValue, false),
            NonceError::UnexpectedValue.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::BadAccountState, false),
            NonceError::BadAccountState.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::NoRecentBlockhashes, true),
            SystemError::NonceNoRecentBlockhashes.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::NotExpired, true),
            SystemError::NonceBlockhashNotExpired.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::UnexpectedValue, true),
            SystemError::NonceUnexpectedBlockhashValue.into(),
        );
        assert_eq!(
            nonce_to_instruction_error(NonceError::BadAccountState, true),
            InstructionError::InvalidAccountData,
        );
    }

    #[test]
    fn test_instruction_to_nonce_error() {
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(NonceErrorAdapter::NoRecentBlockhashes.to_u32().unwrap(),),
                false,
            ),
            Some(NonceError::NoRecentBlockhashes),
        );
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(NonceErrorAdapter::NotExpired.to_u32().unwrap(),),
                false,
            ),
            Some(NonceError::NotExpired),
        );
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(NonceErrorAdapter::UnexpectedValue.to_u32().unwrap(),),
                false,
            ),
            Some(NonceError::UnexpectedValue),
        );
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(NonceErrorAdapter::BadAccountState.to_u32().unwrap(),),
                false,
            ),
            Some(NonceError::BadAccountState),
        );
        assert_eq!(
            instruction_to_nonce_error(&InstructionError::Custom(u32::MAX), false),
            None,
        );
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(SystemError::NonceNoRecentBlockhashes.to_u32().unwrap(),),
                true,
            ),
            Some(NonceError::NoRecentBlockhashes),
        );
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(SystemError::NonceBlockhashNotExpired.to_u32().unwrap(),),
                true,
            ),
            Some(NonceError::NotExpired),
        );
        assert_eq!(
            instruction_to_nonce_error(
                &InstructionError::Custom(
                    SystemError::NonceUnexpectedBlockhashValue.to_u32().unwrap(),
                ),
                true,
            ),
            Some(NonceError::UnexpectedValue),
        );
        assert_eq!(
            instruction_to_nonce_error(&InstructionError::InvalidAccountData, true),
            Some(NonceError::BadAccountState),
        );
        assert_eq!(
            instruction_to_nonce_error(&InstructionError::Custom(u32::MAX), true),
            None,
        );
    }

    #[test]
    fn test_nonce_error_adapter_compat() {
        assert_eq!(
            NonceError::NoRecentBlockhashes.to_u32(),
            NonceErrorAdapter::NoRecentBlockhashes.to_u32(),
        );
        assert_eq!(
            NonceError::NotExpired.to_u32(),
            NonceErrorAdapter::NotExpired.to_u32(),
        );
        assert_eq!(
            NonceError::UnexpectedValue.to_u32(),
            NonceErrorAdapter::UnexpectedValue.to_u32(),
        );
        assert_eq!(
            NonceError::BadAccountState.to_u32(),
            NonceErrorAdapter::BadAccountState.to_u32(),
        );
    }
}
