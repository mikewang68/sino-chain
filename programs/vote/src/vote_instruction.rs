//! Vote program
//! Receive and processes votes from validators

use {
    crate::{
        id,
        vote_state::{self, Vote, VoteAuthorize, VoteInit, VoteState},
    },
    log::*,
    num_derive::{FromPrimitive, ToPrimitive},
    serde_derive::{Deserialize, Serialize},
    metrics::inc_new_counter_info,
    program_runtime::invoke_context::InvokeContext,
    sdk::{
        decode_error::DecodeError,
        feature_set,
        hash::Hash,
        instruction::{AccountMeta, Instruction, InstructionError},
        keyed_account::{
            check_sysvar_keyed_account, from_keyed_account, get_signers, keyed_account_at_index,
            KeyedAccount,
        },
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction,
        sysvar::{self, clock::Clock, rent::Rent, slot_hashes::SlotHashes},
    },
    std::{collections::HashSet, sync::Arc},
    thiserror::Error,
};

/// Reasons the stake might have had an error
#[derive(Error, Debug, Clone, PartialEq, FromPrimitive, ToPrimitive)]
pub enum VoteError {
    #[error("vote already recorded or not in slot hashes history")]
    VoteTooOld,

    #[error("vote slots do not match bank history")]
    SlotsMismatch,

    #[error("vote hash does not match bank hash")]
    SlotHashMismatch,

    #[error("vote has no slots, invalid")]
    EmptySlots,

    #[error("vote timestamp not recent")]
    TimestampTooOld,

    #[error("authorized voter has already been changed this epoch")]
    TooSoonToReauthorize,

    // TODO: figure out how to migrate these new errors
    #[error("Old state had vote which should not have been popped off by vote in new state")]
    LockoutConflict,

    #[error("Proposed state had earlier slot which should have been popped off by later vote")]
    NewVoteStateLockoutMismatch,

    #[error("Vote slots are not ordered")]
    SlotsNotOrdered,

    #[error("Confirmations are not ordered")]
    ConfirmationsNotOrdered,

    #[error("Zero confirmations")]
    ZeroConfirmations,

    #[error("Confirmation exceeds limit")]
    ConfirmationTooLarge,

    #[error("Root rolled back")]
    RootRollBack,

    #[error("Confirmations for same vote were smaller in new proposed state")]
    ConfirmationRollBack,

    #[error("New state contained a vote slot smaller than the root")]
    SlotSmallerThanRoot,

    #[error("New state contained too many votes")]
    TooManyVotes,
}

impl<E> DecodeError<E> for VoteError {
    fn type_of() -> &'static str {
        "VoteError"
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum VoteInstruction {
    /// Initialize a vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Uninitialized vote account
    ///   1. `[]` Rent sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` New validator identity (node_pubkey)
    InitializeAccount(VoteInit),

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    Authorize(Pubkey, VoteAuthorize),

    /// A Vote instruction with recent votes
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to vote with
    ///   1. `[]` Slot hashes sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` Vote authority
    Vote(Vote),

    /// Withdraw some amount of funds
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to withdraw from
    ///   1. `[WRITE]` Recipient account
    ///   2. `[SIGNER]` Withdraw authority
    Withdraw(u64),

    /// Update the vote account's validator identity (node_pubkey)
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the given authority public key
    ///   1. `[SIGNER]` New validator identity (node_pubkey)
    ///   2. `[SIGNER]` Withdraw authority
    UpdateValidatorIdentity,

    /// Update the commission for the vote account
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated
    ///   1. `[SIGNER]` Withdraw authority
    UpdateCommission(u8),

    /// A Vote instruction with recent votes
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to vote with
    ///   1. `[]` Slot hashes sysvar
    ///   2. `[]` Clock sysvar
    ///   3. `[SIGNER]` Vote authority
    VoteSwitch(Vote, Hash),

    /// Authorize a key to send votes or issue a withdrawal
    ///
    /// This instruction behaves like `Authorize` with the additional requirement that the new vote
    /// or withdraw authority must also be a signer.
    ///
    /// # Account references
    ///   0. `[WRITE]` Vote account to be updated with the Pubkey for authorization
    ///   1. `[]` Clock sysvar
    ///   2. `[SIGNER]` Vote or withdraw authority
    ///   3. `[SIGNER]` New vote or withdraw authority
    AuthorizeChecked(VoteAuthorize),
}

fn initialize_account(vote_pubkey: &Pubkey, vote_init: &VoteInit) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::rent::id(), false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(vote_init.node_pubkey, true),
    ];

    Instruction::new_with_bincode(
        id(),
        &VoteInstruction::InitializeAccount(*vote_init),
        account_metas,
    )
}

pub fn create_account(
    from_pubkey: &Pubkey,
    vote_pubkey: &Pubkey,
    vote_init: &VoteInit,
    wens: u64,
) -> Vec<Instruction> {
    let space = VoteState::size_of() as u64;
    let create_ix =
        system_instruction::create_account(from_pubkey, vote_pubkey, wens, space, &id());
    let init_ix = initialize_account(vote_pubkey, vote_init);
    vec![create_ix, init_ix]
}

pub fn create_account_with_seed(
    from_pubkey: &Pubkey,
    vote_pubkey: &Pubkey,
    base: &Pubkey,
    seed: &str,
    vote_init: &VoteInit,
    wens: u64,
) -> Vec<Instruction> {
    let space = VoteState::size_of() as u64;
    let create_ix = system_instruction::create_account_with_seed(
        from_pubkey,
        vote_pubkey,
        base,
        seed,
        wens,
        space,
        &id(),
    );
    let init_ix = initialize_account(vote_pubkey, vote_init);
    vec![create_ix, init_ix]
}

pub fn authorize(
    vote_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey, // currently authorized
    new_authorized_pubkey: &Pubkey,
    vote_authorize: VoteAuthorize,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
    ];

    Instruction::new_with_bincode(
        id(),
        &VoteInstruction::Authorize(*new_authorized_pubkey, vote_authorize),
        account_metas,
    )
}

pub fn authorize_checked(
    vote_pubkey: &Pubkey,
    authorized_pubkey: &Pubkey, // currently authorized
    new_authorized_pubkey: &Pubkey,
    vote_authorize: VoteAuthorize,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*authorized_pubkey, true),
        AccountMeta::new_readonly(*new_authorized_pubkey, true),
    ];

    Instruction::new_with_bincode(
        id(),
        &VoteInstruction::AuthorizeChecked(vote_authorize),
        account_metas,
    )
}

pub fn update_validator_identity(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    node_pubkey: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(*node_pubkey, true),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    Instruction::new_with_bincode(
        id(),
        &VoteInstruction::UpdateValidatorIdentity,
        account_metas,
    )
}

pub fn update_commission(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    commission: u8,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    Instruction::new_with_bincode(
        id(),
        &VoteInstruction::UpdateCommission(commission),
        account_metas,
    )
}

pub fn vote(vote_pubkey: &Pubkey, authorized_voter_pubkey: &Pubkey, vote: Vote) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::slot_hashes::id(), false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*authorized_voter_pubkey, true),
    ];

    Instruction::new_with_bincode(id(), &VoteInstruction::Vote(vote), account_metas)
}

pub fn vote_switch(
    vote_pubkey: &Pubkey,
    authorized_voter_pubkey: &Pubkey,
    vote: Vote,
    proof_hash: Hash,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new_readonly(sysvar::slot_hashes::id(), false),
        AccountMeta::new_readonly(sysvar::clock::id(), false),
        AccountMeta::new_readonly(*authorized_voter_pubkey, true),
    ];

    Instruction::new_with_bincode(
        id(),
        &VoteInstruction::VoteSwitch(vote, proof_hash),
        account_metas,
    )
}

pub fn withdraw(
    vote_pubkey: &Pubkey,
    authorized_withdrawer_pubkey: &Pubkey,
    wens: u64,
    to_pubkey: &Pubkey,
) -> Instruction {
    let account_metas = vec![
        AccountMeta::new(*vote_pubkey, false),
        AccountMeta::new(*to_pubkey, false),
        AccountMeta::new_readonly(*authorized_withdrawer_pubkey, true),
    ];

    Instruction::new_with_bincode(id(), &VoteInstruction::Withdraw(wens), account_metas)
}

fn verify_rent_exemption(
    keyed_account: &KeyedAccount,
    rent: &Rent,
) -> Result<(), InstructionError> {
    if !rent.is_exempt(keyed_account.wens()?, keyed_account.data_len()?) {
        Err(InstructionError::InsufficientFunds)
    } else {
        Ok(())
    }
}

/// These methods facilitate a transition from fetching sysvars from keyed
/// accounts to fetching from the sysvar cache without breaking consensus. In
/// order to keep consistent behavior, they continue to enforce the same checks
/// as `sdk::keyed_account::from_keyed_account` despite dynamically
/// loading them instead of deserializing from account data.
mod get_sysvar_with_keyed_account_check {
    use super::*;

    pub fn clock(
        keyed_account: &KeyedAccount,
        invoke_context: &InvokeContext,
    ) -> Result<Arc<Clock>, InstructionError> {
        check_sysvar_keyed_account::<Clock>(keyed_account)?;
        invoke_context.get_sysvar_cache().get_clock()
    }

    pub fn rent(
        keyed_account: &KeyedAccount,
        invoke_context: &InvokeContext,
    ) -> Result<Arc<Rent>, InstructionError> {
        check_sysvar_keyed_account::<Rent>(keyed_account)?;
        invoke_context.get_sysvar_cache().get_rent()
    }

    pub fn slot_hashes(
        keyed_account: &KeyedAccount,
        invoke_context: &InvokeContext,
    ) -> Result<Arc<SlotHashes>, InstructionError> {
        check_sysvar_keyed_account::<SlotHashes>(keyed_account)?;
        invoke_context.get_sysvar_cache().get_slot_hashes()
    }
}

pub fn process_instruction(
    first_instruction_account: usize,
    data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;

    trace!("process_instruction: {:?}", data);
    trace!("keyed_accounts: {:?}", keyed_accounts);

    let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    if me.owner()? != id() {
        return Err(InstructionError::InvalidAccountOwner);
    }

    let signers: HashSet<Pubkey> = get_signers(&keyed_accounts[first_instruction_account..]);
    match limited_deserialize(data)? {
        VoteInstruction::InitializeAccount(vote_init) => {
            let rent = get_sysvar_with_keyed_account_check::rent(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            verify_rent_exemption(me, &rent)?;
            let clock = get_sysvar_with_keyed_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            vote_state::initialize_account(me, &vote_init, &signers, &clock)
        }
        VoteInstruction::Authorize(voter_pubkey, vote_authorize) => {
            let clock = get_sysvar_with_keyed_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            vote_state::authorize(
                me,
                &voter_pubkey,
                vote_authorize,
                &signers,
                &clock,
                &invoke_context.feature_set,
            )
        }
        VoteInstruction::UpdateValidatorIdentity => vote_state::update_validator_identity(
            me,
            keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?.unsigned_key(),
            &signers,
        ),
        VoteInstruction::UpdateCommission(commission) => {
            vote_state::update_commission(me, commission, &signers)
        }
        VoteInstruction::Vote(vote) | VoteInstruction::VoteSwitch(vote, _) => {
            inc_new_counter_info!("vote-native", 1);
            let slot_hashes = get_sysvar_with_keyed_account_check::slot_hashes(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
                invoke_context,
            )?;
            let clock = get_sysvar_with_keyed_account_check::clock(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
                invoke_context,
            )?;
            vote_state::process_vote(me, &slot_hashes, &clock, &vote, &signers)
        }
        VoteInstruction::Withdraw(wens) => {
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let rent_sysvar = if invoke_context
                .feature_set
                .is_active(&feature_set::reject_non_rent_exempt_vote_withdraws::id())
            {
                Some(invoke_context.get_sysvar_cache().get_rent()?)
            } else {
                None
            };
            let clock_if_feature_active = if invoke_context
                .feature_set
                .is_active(&feature_set::reject_vote_account_close_unless_zero_credit_epoch::id())
            {
                Some(invoke_context.get_sysvar_cache().get_clock()?)
            } else {
                None
            };
            vote_state::withdraw(
                me,
                wens,
                to,
                &signers,
                rent_sysvar.as_deref(),
                clock_if_feature_active.as_deref(),
            )
        }
        VoteInstruction::AuthorizeChecked(vote_authorize) => {
            if invoke_context
                .feature_set
                .is_active(&feature_set::vote_stake_checked_instructions::id())
            {
                let voter_pubkey =
                    &keyed_account_at_index(keyed_accounts, first_instruction_account + 3)?
                        .signer_key()
                        .ok_or(InstructionError::MissingRequiredSignature)?;
                vote_state::authorize(
                    me,
                    voter_pubkey,
                    vote_authorize,
                    &signers,
                    &from_keyed_account::<Clock>(keyed_account_at_index(
                        keyed_accounts,
                        first_instruction_account + 1,
                    )?)?,
                    &invoke_context.feature_set,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        bincode::serialize,
        program_runtime::{
            invoke_context::mock_process_instruction, sysvar_cache::SysvarCache,
        },
        sdk::{
            account::{self, Account, AccountSharedData},
            rent::Rent,
        },
        std::{cell::RefCell, rc::Rc, str::FromStr},
    };

    fn create_default_account() -> Rc<RefCell<AccountSharedData>> {
        AccountSharedData::new_ref(0, 0, &Pubkey::new_unique())
    }

    fn process_instruction(
        instruction_data: &[u8],
        keyed_accounts: &[(bool, bool, Pubkey, Rc<RefCell<AccountSharedData>>)],
    ) -> Result<(), InstructionError> {
        mock_process_instruction(
            &id(),
            Vec::new(),
            instruction_data,
            keyed_accounts,
            super::process_instruction,
        )
    }

    fn process_instruction_as_one_arg(instruction: &Instruction) -> Result<(), InstructionError> {
        let mut accounts: Vec<_> = instruction
            .accounts
            .iter()
            .map(|meta| {
                Rc::new(RefCell::new(if sysvar::clock::check_id(&meta.pubkey) {
                    account::create_account_shared_data_for_test(&Clock::default())
                } else if sysvar::slot_hashes::check_id(&meta.pubkey) {
                    account::create_account_shared_data_for_test(&SlotHashes::default())
                } else if sysvar::rent::check_id(&meta.pubkey) {
                    account::create_account_shared_data_for_test(&Rent::free())
                } else if meta.pubkey == invalid_vote_state_pubkey() {
                    AccountSharedData::from(Account {
                        owner: invalid_vote_state_pubkey(),
                        ..Account::default()
                    })
                } else {
                    AccountSharedData::from(Account {
                        owner: id(),
                        ..Account::default()
                    })
                }))
            })
            .collect();
        #[allow(clippy::same_item_push)]
        for _ in 0..instruction.accounts.len() {
            accounts.push(AccountSharedData::new_ref(0, 0, &Pubkey::new_unique()));
        }
        let keyed_accounts: Vec<_> = instruction
            .accounts
            .iter()
            .zip(accounts.into_iter())
            .map(|(meta, account)| (meta.is_signer, meta.is_writable, meta.pubkey, account))
            .collect();

        let mut sysvar_cache = SysvarCache::default();
        sysvar_cache.set_rent(Rent::free());
        sysvar_cache.set_clock(Clock::default());
        sysvar_cache.set_slot_hashes(SlotHashes::default());
        program_runtime::invoke_context::mock_process_instruction_with_sysvars(
            &id(),
            Vec::new(),
            &instruction.data,
            &keyed_accounts,
            &sysvar_cache,
            super::process_instruction,
        )
    }

    fn invalid_vote_state_pubkey() -> Pubkey {
        Pubkey::from_str("BadVote111111111111111111111111111111111111").unwrap()
    }

    // these are for 100% coverage in this file
    #[test]
    fn test_vote_process_instruction_decode_bail() {
        assert_eq!(
            process_instruction(&[], &[]),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_spoofed_vote() {
        assert_eq!(
            process_instruction_as_one_arg(&vote(
                &invalid_vote_state_pubkey(),
                &Pubkey::new_unique(),
                Vote::default(),
            )),
            Err(InstructionError::InvalidAccountOwner),
        );
    }

    #[test]
    fn test_vote_process_instruction() {
        sino_logger::setup();
        let instructions = create_account(
            &Pubkey::new_unique(),
            &Pubkey::new_unique(),
            &VoteInit::default(),
            100,
        );
        assert_eq!(
            process_instruction_as_one_arg(&instructions[1]),
            Err(InstructionError::InvalidAccountData),
        );
        assert_eq!(
            process_instruction_as_one_arg(&vote(
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                Vote::default(),
            )),
            Err(InstructionError::InvalidAccountData),
        );
        assert_eq!(
            process_instruction_as_one_arg(&vote_switch(
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                Vote::default(),
                Hash::default(),
            )),
            Err(InstructionError::InvalidAccountData),
        );
        assert_eq!(
            process_instruction_as_one_arg(&authorize(
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                VoteAuthorize::Voter,
            )),
            Err(InstructionError::InvalidAccountData),
        );
        assert_eq!(
            process_instruction_as_one_arg(&update_validator_identity(
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
            )),
            Err(InstructionError::InvalidAccountData),
        );
        assert_eq!(
            process_instruction_as_one_arg(&update_commission(
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                0,
            )),
            Err(InstructionError::InvalidAccountData),
        );

        assert_eq!(
            process_instruction_as_one_arg(&withdraw(
                &Pubkey::new_unique(),
                &Pubkey::new_unique(),
                0,
                &Pubkey::new_unique()
            )),
            Err(InstructionError::InvalidAccountData),
        );
    }

    #[test]
    fn test_vote_authorize_checked() {
        let vote_pubkey = Pubkey::new_unique();
        let authorized_pubkey = Pubkey::new_unique();
        let new_authorized_pubkey = Pubkey::new_unique();

        // Test with vanilla authorize accounts
        let mut instruction = authorize_checked(
            &vote_pubkey,
            &authorized_pubkey,
            &new_authorized_pubkey,
            VoteAuthorize::Voter,
        );
        instruction.accounts = instruction.accounts[0..2].to_vec();
        assert_eq!(
            process_instruction_as_one_arg(&instruction),
            Err(InstructionError::NotEnoughAccountKeys),
        );

        let mut instruction = authorize_checked(
            &vote_pubkey,
            &authorized_pubkey,
            &new_authorized_pubkey,
            VoteAuthorize::Withdrawer,
        );
        instruction.accounts = instruction.accounts[0..2].to_vec();
        assert_eq!(
            process_instruction_as_one_arg(&instruction),
            Err(InstructionError::NotEnoughAccountKeys),
        );

        // Test with non-signing new_authorized_pubkey
        let mut instruction = authorize_checked(
            &vote_pubkey,
            &authorized_pubkey,
            &new_authorized_pubkey,
            VoteAuthorize::Voter,
        );
        instruction.accounts[3] = AccountMeta::new_readonly(new_authorized_pubkey, false);
        assert_eq!(
            process_instruction_as_one_arg(&instruction),
            Err(InstructionError::MissingRequiredSignature),
        );

        let mut instruction = authorize_checked(
            &vote_pubkey,
            &authorized_pubkey,
            &new_authorized_pubkey,
            VoteAuthorize::Withdrawer,
        );
        instruction.accounts[3] = AccountMeta::new_readonly(new_authorized_pubkey, false);
        assert_eq!(
            process_instruction_as_one_arg(&instruction),
            Err(InstructionError::MissingRequiredSignature),
        );

        // Test with new_authorized_pubkey signer
        let vote_account = AccountSharedData::new_ref(100, VoteState::size_of(), &id());
        let clock_address = sysvar::clock::id();
        let clock_account = Rc::new(RefCell::new(account::create_account_shared_data_for_test(
            &Clock::default(),
        )));
        let default_authorized_pubkey = Pubkey::default();
        let authorized_account = create_default_account();
        let new_authorized_account = create_default_account();
        let keyed_accounts = [
            (false, false, vote_pubkey, vote_account),
            (false, false, clock_address, clock_account),
            (true, false, default_authorized_pubkey, authorized_account),
            (true, false, new_authorized_pubkey, new_authorized_account),
        ];
        assert_eq!(
            process_instruction(
                &serialize(&VoteInstruction::AuthorizeChecked(VoteAuthorize::Voter)).unwrap(),
                &keyed_accounts,
            ),
            Ok(())
        );

        assert_eq!(
            process_instruction(
                &serialize(&VoteInstruction::AuthorizeChecked(
                    VoteAuthorize::Withdrawer
                ))
                .unwrap(),
                &keyed_accounts,
            ),
            Ok(())
        );
    }

    #[test]
    fn test_minimum_balance() {
        let rent = Rent::default();
        let minimum_balance = rent.minimum_balance(VoteState::size_of());
        // golden, may need updating when vote_state grows
        assert!(minimum_balance as f64 / 10f64.powf(9.0) < 0.04)
    }

    #[test]
    fn test_custom_error_decode() {
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
            "Custom(0): VoteError::VoteTooOld - vote already recorded or not in slot hashes history",
            pretty_err::<VoteError>(VoteError::VoteTooOld.into())
        )
    }
}
