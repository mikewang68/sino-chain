use {
    crate::nonce_keyed_account::NonceKeyedAccount,
    log::*,
    program_runtime::{ic_msg, invoke_context::InvokeContext},
    sdk::{
        account::{AccountSharedData, ReadableAccount, WritableAccount},
        account_utils::{State as _, StateMut},
        feature_set,
        instruction::InstructionError,
        keyed_account::{from_keyed_account, get_signers, keyed_account_at_index, KeyedAccount},
        nonce,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        system_instruction::{
            NonceError, SystemError, SystemInstruction, MAX_PERMITTED_DATA_LENGTH,
        },
        system_program,
        sysvar::{self, rent::Rent},
    },
    std::collections::HashSet,
};

// represents an address that may or may not have been generated
//  from a seed
#[derive(PartialEq, Default, Debug)]
struct Address {
    address: Pubkey,
    base: Option<Pubkey>,
}

impl Address {
    fn is_signer(&self, signers: &HashSet<Pubkey>) -> bool {
        if let Some(base) = self.base {
            signers.contains(&base)
        } else {
            signers.contains(&self.address)
        }
    }
    fn create(
        address: &Pubkey,
        with_seed: Option<(&Pubkey, &str, &Pubkey)>,
        invoke_context: &InvokeContext,
    ) -> Result<Self, InstructionError> {
        let base = if let Some((base, seed, owner)) = with_seed {
            let address_with_seed = Pubkey::create_with_seed(base, seed, owner)?;
            // re-derive the address, must match the supplied address
            if *address != address_with_seed {
                ic_msg!(
                    invoke_context,
                    "Create: address {} does not match derived address {}",
                    address,
                    address_with_seed
                );
                return Err(SystemError::AddressWithSeedMismatch.into());
            }
            Some(*base)
        } else {
            None
        };

        Ok(Self {
            address: *address,
            base,
        })
    }
}

fn allocate(
    account: &mut AccountSharedData,
    address: &Address,
    space: u64,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !address.is_signer(signers) {
        ic_msg!(
            invoke_context,
            "Allocate: 'to' account {:?} must sign",
            address
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    // if it looks like the `to` account is already in use, bail
    //   (note that the id check is also enforced by message_processor)
    if !account.data().is_empty() || !system_program::check_id(account.owner()) {
        ic_msg!(
            invoke_context,
            "Allocate: account {:?} already in use",
            address
        );
        return Err(SystemError::AccountAlreadyInUse.into());
    }

    if space > MAX_PERMITTED_DATA_LENGTH {
        ic_msg!(
            invoke_context,
            "Allocate: requested {}, max allowed {}",
            space,
            MAX_PERMITTED_DATA_LENGTH
        );
        return Err(SystemError::InvalidAccountDataLength.into());
    }

    account.set_data(vec![0; space as usize]);

    Ok(())
}

fn assign(
    account: &mut AccountSharedData,
    address: &Address,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    // no work to do, just return
    if account.owner() == owner {
        return Ok(());
    }

    if !address.is_signer(signers) {
        ic_msg!(invoke_context, "Assign: account {:?} must sign", address);
        return Err(InstructionError::MissingRequiredSignature);
    }

    // bpf programs are allowed to do this; so this is inconsistent...
    // Thus, we're starting to remove this restriction from system instruction
    // processor for consistency and fewer special casing by piggybacking onto
    // the related feature gate..
    let rent_for_sysvars = invoke_context
        .feature_set
        .is_active(&feature_set::rent_for_sysvars::id());
    if !rent_for_sysvars && sysvar::check_id(owner) {
        // guard against sysvars being made
        ic_msg!(invoke_context, "Assign: cannot assign to sysvar, {}", owner);
        return Err(SystemError::InvalidProgramId.into());
    }

    account.set_owner(*owner);
    Ok(())
}

fn allocate_and_assign(
    to: &mut AccountSharedData,
    to_address: &Address,
    space: u64,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    allocate(to, to_address, space, signers, invoke_context)?;
    assign(to, to_address, owner, signers, invoke_context)
}

fn create_account(
    from: &KeyedAccount,
    to: &KeyedAccount,
    to_address: &Address,
    lamports: u64,
    space: u64,
    owner: &Pubkey,
    signers: &HashSet<Pubkey>,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    // if it looks like the `to` account is already in use, bail
    {
        let to = &mut to.try_account_ref_mut()?;
        if to.wens() > 0 {
            ic_msg!(
                invoke_context,
                "Create Account: account {:?} already in use",
                to_address
            );
            return Err(SystemError::AccountAlreadyInUse.into());
        }

        allocate_and_assign(to, to_address, space, owner, signers, invoke_context)?;
    }
    transfer(from, to, lamports, invoke_context)
}

fn transfer_verified(
    from: &KeyedAccount,
    to: &KeyedAccount,
    lamports: u64,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !from.data_is_empty()? {
        ic_msg!(invoke_context, "Transfer: `from` must not carry data");
        return Err(InstructionError::InvalidArgument);
    }
    if lamports > from.lamports()? {
        ic_msg!(
            invoke_context,
            "Transfer: insufficient lamports {}, need {}",
            from.lamports()?,
            lamports
        );
        return Err(SystemError::ResultWithNegativeLamports.into());
    }

    from.try_account_ref_mut()?.checked_sub_lamports(lamports)?;
    to.try_account_ref_mut()?.checked_add_lamports(lamports)?;
    Ok(())
}

fn transfer(
    from: &KeyedAccount,
    to: &KeyedAccount,
    lamports: u64,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !invoke_context
        .feature_set
        .is_active(&feature_set::system_transfer_zero_check::id())
        && lamports == 0
    {
        return Ok(());
    }

    if from.signer_key().is_none() {
        ic_msg!(
            invoke_context,
            "Transfer: `from` account {} must sign",
            from.unsigned_key()
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    transfer_verified(from, to, lamports, invoke_context)
}

fn transfer_with_seed(
    from: &KeyedAccount,
    from_base: &KeyedAccount,
    from_seed: &str,
    from_owner: &Pubkey,
    to: &KeyedAccount,
    lamports: u64,
    invoke_context: &InvokeContext,
) -> Result<(), InstructionError> {
    if !invoke_context
        .feature_set
        .is_active(&feature_set::system_transfer_zero_check::id())
        && lamports == 0
    {
        return Ok(());
    }

    if from_base.signer_key().is_none() {
        ic_msg!(
            invoke_context,
            "Transfer: 'from' account {:?} must sign",
            from_base
        );
        return Err(InstructionError::MissingRequiredSignature);
    }

    let address_from_seed =
        Pubkey::create_with_seed(from_base.unsigned_key(), from_seed, from_owner)?;
    if *from.unsigned_key() != address_from_seed {
        ic_msg!(
            invoke_context,
            "Transfer: 'from' address {} does not match derived address {}",
            from.unsigned_key(),
            address_from_seed
        );
        return Err(SystemError::AddressWithSeedMismatch.into());
    }

    transfer_verified(from, to, lamports, invoke_context)
}

pub fn process_instruction(
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let keyed_accounts = invoke_context.get_keyed_accounts()?;
    let instruction = limited_deserialize(instruction_data)?;

    trace!("process_instruction: {:?}", instruction);
    trace!("keyed_accounts: {:?}", keyed_accounts);

    let _ = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
    let signers = get_signers(&keyed_accounts[first_instruction_account..]);
    match instruction {
        SystemInstruction::CreateAccount {
            lamports,
            space,
            owner,
        } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let to_address = Address::create(to.unsigned_key(), None, invoke_context)?;
            create_account(
                from,
                to,
                &to_address,
                lamports,
                space,
                &owner,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::CreateAccountWithSeed {
            base,
            seed,
            lamports,
            space,
            owner,
        } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let to_address = Address::create(
                to.unsigned_key(),
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            create_account(
                from,
                to,
                &to_address,
                lamports,
                space,
                &owner,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::Assign { owner } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(keyed_account.unsigned_key(), None, invoke_context)?;
            assign(&mut account, &address, &owner, &signers, invoke_context)
        }
        SystemInstruction::Transfer { lamports } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            transfer(from, to, lamports, invoke_context)
        }
        SystemInstruction::TransferWithSeed {
            lamports,
            from_seed,
            from_owner,
        } => {
            let from = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let base = keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            let to = keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?;
            transfer_with_seed(
                from,
                base,
                &from_seed,
                &from_owner,
                to,
                lamports,
                invoke_context,
            )
        }
        SystemInstruction::AdvanceNonceAccount => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            #[allow(deprecated)]
            if from_keyed_account::<sdk::sysvar::recent_blockhashes::RecentBlockhashes>(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
            )?
            .is_empty()
            {
                ic_msg!(
                    invoke_context,
                    "Advance nonce account: recent blockhash list is empty",
                );
                return Err(NonceError::NoRecentBlockhashes.into());
            }
            me.advance_nonce_account(&signers, invoke_context)
        }
        SystemInstruction::WithdrawNonceAccount(lamports) => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let to = &mut keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?;
            #[allow(deprecated)]
            let _ = from_keyed_account::<sdk::sysvar::recent_blockhashes::RecentBlockhashes>(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 2)?,
            )?;
            me.withdraw_nonce_account(
                lamports,
                to,
                &from_keyed_account::<Rent>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 3,
                )?)?,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::InitializeNonceAccount(authorized) => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            #[allow(deprecated)]
            if from_keyed_account::<sdk::sysvar::recent_blockhashes::RecentBlockhashes>(
                keyed_account_at_index(keyed_accounts, first_instruction_account + 1)?,
            )?
            .is_empty()
            {
                ic_msg!(
                    invoke_context,
                    "Initialize nonce account: recent blockhash list is empty",
                );
                return Err(NonceError::NoRecentBlockhashes.into());
            }
            me.initialize_nonce_account(
                &authorized,
                &from_keyed_account::<Rent>(keyed_account_at_index(
                    keyed_accounts,
                    first_instruction_account + 2,
                )?)?,
                invoke_context,
            )
        }
        SystemInstruction::AuthorizeNonceAccount(nonce_authority) => {
            let me = &mut keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            me.authorize_nonce_account(&nonce_authority, &signers, invoke_context)
        }
        SystemInstruction::UpgradeNonceAccount => {
            let separate_nonce_from_blockhash = invoke_context
                .feature_set
                .is_active(&feature_set::separate_nonce_from_blockhash::id());
            if !separate_nonce_from_blockhash {
                return Err(InstructionError::InvalidInstructionData);
            }
            let nonce_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            if !system_program::check_id(&nonce_account.owner()?) {
                return Err(InstructionError::InvalidAccountOwner);
            }
            if !nonce_account.is_writable() {
                return Err(InstructionError::InvalidArgument);
            }
            let nonce_versions: nonce::state::Versions = nonce_account.state()?;
            match nonce_versions.upgrade() {
                None => Err(InstructionError::InvalidArgument),
                Some(nonce_versions) => nonce_account.set_state(&nonce_versions),
            }
        }
        SystemInstruction::Allocate { space } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(keyed_account.unsigned_key(), None, invoke_context)?;
            allocate(&mut account, &address, space, &signers, invoke_context)
        }
        SystemInstruction::AllocateWithSeed {
            base,
            seed,
            space,
            owner,
        } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(
                keyed_account.unsigned_key(),
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            allocate_and_assign(
                &mut account,
                &address,
                space,
                &owner,
                &signers,
                invoke_context,
            )
        }
        SystemInstruction::AssignWithSeed { base, seed, owner } => {
            let keyed_account = keyed_account_at_index(keyed_accounts, first_instruction_account)?;
            let mut account = keyed_account.try_account_ref_mut()?;
            let address = Address::create(
                keyed_account.unsigned_key(),
                Some((&base, &seed, &owner)),
                invoke_context,
            )?;
            assign(&mut account, &address, &owner, &signers, invoke_context)
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemAccountKind {
    System,
    Nonce,
}

pub fn get_system_account_kind(account: &AccountSharedData) -> Option<SystemAccountKind> {
    if system_program::check_id(account.owner()) {
        if account.data().is_empty() {
            Some(SystemAccountKind::System)
        } else if account.data().len() == nonce::State::size() {
            let nonce_versions: nonce::state::Versions = account.state().ok()?;
            match nonce_versions.state() {
                nonce::State::Uninitialized => None,
                nonce::State::Initialized(_) => Some(SystemAccountKind::Nonce),
            }
        } else {
            None
        }
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    #[allow(deprecated)]
    use sdk::{
        account::{self, Account, AccountSharedData},
        client::SyncClient,
        feature_set::FeatureSet,
        fee_calculator::FeeCalculator,
        genesis_config::create_genesis_config,
        hash::{hash, hashv, Hash},
        instruction::{AccountMeta, Instruction, InstructionError},
        message::Message,
        nonce::{
            self,
            state::{
                Data as NonceData, DurableNonce, State as NonceState, Versions as NonceVersions,
            },
        },
        nonce_account, recent_blockhashes_account,
        signature::{Keypair, Signer},
        system_instruction, system_program, sysvar,
        sysvar::recent_blockhashes::IterItem,
        transaction::TransactionError,
    };
    use {
        super::*,
        crate::{bank::Bank, bank_client::BankClient},
        bincode::serialize,
        program_runtime::invoke_context::{mock_process_instruction, InvokeContext},
        std::{cell::RefCell, rc::Rc, sync::Arc},
    };

    impl From<Pubkey> for Address {
        fn from(address: Pubkey) -> Self {
            Self {
                address,
                base: None,
            }
        }
    }

    fn process_instruction(
        instruction_data: &[u8],
        keyed_accounts: &[(bool, bool, Pubkey, Rc<RefCell<AccountSharedData>>)],
    ) -> Result<(), InstructionError> {
        mock_process_instruction(
            &system_program::id(),
            Vec::new(),
            instruction_data,
            keyed_accounts,
            super::process_instruction,
        )
    }

    fn create_default_account() -> Rc<RefCell<AccountSharedData>> {
        AccountSharedData::new_ref(0, 0, &Pubkey::new_unique())
    }
    fn create_default_recent_blockhashes_account() -> Rc<RefCell<AccountSharedData>> {
        Rc::new(RefCell::new(
            #[allow(deprecated)]
            recent_blockhashes_account::create_account_with_data_for_test(
                vec![IterItem(0u64, &Hash::default(), 0); sysvar::recent_blockhashes::MAX_ENTRIES]
                    .into_iter(),
            ),
        ))
    }
    fn create_default_rent_account() -> Rc<RefCell<AccountSharedData>> {
        Rc::new(RefCell::new(account::create_account_shared_data_for_test(
            &Rent::free(),
        )))
    }

    #[test]
    fn test_create_account() {
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let to = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());
        let to_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());

        assert_eq!(
            process_instruction(
                &bincode::serialize(&SystemInstruction::CreateAccount {
                    lamports: 50,
                    space: 2,
                    owner: new_owner
                })
                .unwrap(),
                &[
                    (true, false, from, from_account.clone()),
                    (true, false, to, to_account.clone()),
                ],
            ),
            Ok(())
        );
        assert_eq!(from_account.borrow().wens(), 50);
        assert_eq!(to_account.borrow().wens(), 50);
        assert_eq!(to_account.borrow().owner(), &new_owner);
        assert_eq!(to_account.borrow().data(), &[0, 0]);
    }

    #[test]
    fn test_create_account_with_seed() {
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let seed = "shiny pepper";
        let to = Pubkey::create_with_seed(&from, seed, &new_owner).unwrap();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());
        let to_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());

        assert_eq!(
            process_instruction(
                &bincode::serialize(&SystemInstruction::CreateAccountWithSeed {
                    base: from,
                    seed: seed.to_string(),
                    lamports: 50,
                    space: 2,
                    owner: new_owner
                })
                .unwrap(),
                &[
                    (true, false, from, from_account.clone()),
                    (false, false, to, to_account.clone()),
                ],
            ),
            Ok(())
        );
        assert_eq!(from_account.borrow().wens(), 50);
        assert_eq!(to_account.borrow().wens(), 50);
        assert_eq!(to_account.borrow().owner(), &new_owner);
        assert_eq!(to_account.borrow().data(), &[0, 0]);
    }

    #[test]
    fn test_create_account_with_seed_separate_base_account() {
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let base = Pubkey::new_unique();
        let seed = "shiny pepper";
        let to = Pubkey::create_with_seed(&base, seed, &new_owner).unwrap();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());
        let to_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());
        let base_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());

        assert_eq!(
            process_instruction(
                &bincode::serialize(&SystemInstruction::CreateAccountWithSeed {
                    base,
                    seed: seed.to_string(),
                    lamports: 50,
                    space: 2,
                    owner: new_owner
                })
                .unwrap(),
                &[
                    (true, false, from, from_account.clone()),
                    (false, false, to, to_account.clone()),
                    (true, false, base, base_account),
                ],
            ),
            Ok(())
        );
        assert_eq!(from_account.borrow().wens(), 50);
        assert_eq!(to_account.borrow().wens(), 50);
        assert_eq!(to_account.borrow().owner(), &new_owner);
        assert_eq!(to_account.borrow().data(), &[0, 0]);
    }

    #[test]
    fn test_address_create_with_seed_mismatch() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let from = Pubkey::new_unique();
        let seed = "dull boy";
        let to = Pubkey::new_unique();
        let owner = Pubkey::new_unique();

        assert_eq!(
            Address::create(&to, Some((&from, seed, &owner)), &invoke_context),
            Err(SystemError::AddressWithSeedMismatch.into())
        );
    }

    #[test]
    fn test_create_account_with_seed_missing_sig() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let seed = "dull boy";
        let to = Pubkey::create_with_seed(&from, seed, &new_owner).unwrap();

        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());
        let to_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());
        let to_address =
            Address::create(&to, Some((&from, seed, &new_owner)), &invoke_context).unwrap();

        assert_eq!(
            create_account(
                &KeyedAccount::new(&from, false, &from_account),
                &KeyedAccount::new(&to, false, &to_account),
                &to_address,
                50,
                2,
                &new_owner,
                &HashSet::new(),
                &invoke_context,
            ),
            Err(InstructionError::MissingRequiredSignature)
        );
        assert_eq!(from_account.borrow().wens(), 100);
        assert_eq!(*to_account.borrow(), AccountSharedData::default());
    }

    #[test]
    fn test_create_with_zero_lamports() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        // create account with zero lamports transferred
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &Pubkey::new_unique()); // not from system account

        let to = Pubkey::new_unique();
        let to_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());

        assert_eq!(
            create_account(
                &KeyedAccount::new(&from, true, &from_account),
                &KeyedAccount::new(&to, true, &to_account),
                &to.into(),
                0,
                2,
                &new_owner,
                &[from, to].iter().cloned().collect::<HashSet<_>>(),
                &invoke_context,
            ),
            Ok(())
        );

        let from_lamports = from_account.borrow().wens();
        let to_lamports = to_account.borrow().wens();
        let to_owner = *to_account.borrow().owner();
        assert_eq!(from_lamports, 100);
        assert_eq!(to_lamports, 0);
        assert_eq!(to_owner, new_owner);
        assert_eq!(to_account.borrow().data(), &[0, 0]);
    }

    #[test]
    fn test_create_negative_lamports() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        // Attempt to create account with more lamports than remaining in from_account
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());

        let to = Pubkey::new_unique();
        let to_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());

        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&from, false, &to_account),
            &to.into(),
            150,
            2,
            &new_owner,
            &[from, to].iter().cloned().collect::<HashSet<_>>(),
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::ResultWithNegativeLamports.into()));
    }

    #[test]
    fn test_request_more_than_allowed_data_length() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());
        let from = Pubkey::new_unique();
        let to_account = AccountSharedData::new_ref(0, 0, &system_program::id());
        let to = Pubkey::new_unique();

        let signers = &[from, to].iter().cloned().collect::<HashSet<_>>();
        let address = &to.into();

        // Trying to request more data length than permitted will result in failure
        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&to, false, &to_account),
            address,
            50,
            MAX_PERMITTED_DATA_LENGTH + 1,
            &system_program::id(),
            signers,
            &invoke_context,
        );
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            SystemError::InvalidAccountDataLength.into()
        );

        // Trying to request equal or less data length than permitted will be successful
        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&to, false, &to_account),
            address,
            50,
            MAX_PERMITTED_DATA_LENGTH,
            &system_program::id(),
            signers,
            &invoke_context,
        );
        assert!(result.is_ok());
        assert_eq!(to_account.borrow().wens(), 50);
        assert_eq!(
            to_account.borrow().data().len() as u64,
            MAX_PERMITTED_DATA_LENGTH
        );
    }

    #[test]
    fn test_create_already_in_use() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        // Attempt to create system account in account already owned by another program
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());

        let original_program_owner = Pubkey::new(&[5; 32]);
        let owned_key = Pubkey::new_unique();
        let owned_account = AccountSharedData::new_ref(0, 0, &original_program_owner);
        let unchanged_account = owned_account.clone();

        let signers = &[from, owned_key].iter().cloned().collect::<HashSet<_>>();
        let owned_address = owned_key.into();

        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&owned_key, false, &owned_account),
            &owned_address,
            50,
            2,
            &new_owner,
            signers,
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::AccountAlreadyInUse.into()));

        let from_lamports = from_account.borrow().wens();
        assert_eq!(from_lamports, 100);
        assert_eq!(owned_account, unchanged_account);

        // Attempt to create system account in account that already has data
        let owned_account = AccountSharedData::new_ref(0, 1, &Pubkey::default());
        let unchanged_account = owned_account.borrow().clone();
        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&owned_key, false, &owned_account),
            &owned_address,
            50,
            2,
            &new_owner,
            signers,
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::AccountAlreadyInUse.into()));
        let from_lamports = from_account.borrow().wens();
        assert_eq!(from_lamports, 100);
        assert_eq!(*owned_account.borrow(), unchanged_account);

        // Attempt to create an account that already has lamports
        let owned_account = AccountSharedData::new_ref(1, 0, &Pubkey::default());
        let unchanged_account = owned_account.borrow().clone();
        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&owned_key, false, &owned_account),
            &owned_address,
            50,
            2,
            &new_owner,
            signers,
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::AccountAlreadyInUse.into()));
        assert_eq!(from_lamports, 100);
        assert_eq!(*owned_account.borrow(), unchanged_account);
    }

    #[test]
    fn test_create_unsigned() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        // Attempt to create an account without signing the transfer
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());

        let owned_key = Pubkey::new_unique();
        let owned_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());

        let owned_address = owned_key.into();

        // Haven't signed from account
        let result = create_account(
            &KeyedAccount::new(&from, false, &from_account),
            &KeyedAccount::new(&owned_key, false, &owned_account),
            &owned_address,
            50,
            2,
            &new_owner,
            &[owned_key].iter().cloned().collect::<HashSet<_>>(),
            &invoke_context,
        );
        assert_eq!(result, Err(InstructionError::MissingRequiredSignature));

        // Haven't signed to account
        let owned_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());
        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&owned_key, true, &owned_account),
            &owned_address,
            50,
            2,
            &new_owner,
            &[from].iter().cloned().collect::<HashSet<_>>(),
            &invoke_context,
        );
        assert_eq!(result, Err(InstructionError::MissingRequiredSignature));

        // Don't support unsigned creation with zero lamports (ephemeral account)
        let owned_account = AccountSharedData::new_ref(0, 0, &Pubkey::default());
        let result = create_account(
            &KeyedAccount::new(&from, false, &from_account),
            &KeyedAccount::new(&owned_key, true, &owned_account),
            &owned_address,
            0,
            2,
            &new_owner,
            &[owned_key].iter().cloned().collect::<HashSet<_>>(),
            &invoke_context,
        );
        assert_eq!(result, Err(InstructionError::MissingRequiredSignature));
    }

    #[test]
    fn test_create_sysvar_invalid_id_with_feature() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        // Attempt to create system account in account already owned by another program
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());

        let to = Pubkey::new_unique();
        let to_account = AccountSharedData::new_ref(0, 0, &system_program::id());

        let signers = [from, to].iter().cloned().collect::<HashSet<_>>();
        let to_address = to.into();

        // fail to create a sysvar::id() owned account
        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&to, false, &to_account),
            &to_address,
            50,
            2,
            &sysvar::id(),
            &signers,
            &invoke_context,
        );
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn test_create_sysvar_invalid_id_without_feature() {
        let mut feature_set = FeatureSet::all_enabled();
        feature_set
            .active
            .remove(&feature_set::rent_for_sysvars::id());
        feature_set
            .inactive
            .insert(feature_set::rent_for_sysvars::id());
        let mut invoke_context = InvokeContext::new_mock(&[], &[]);
        invoke_context.feature_set = Arc::new(feature_set);
        // Attempt to create system account in account already owned by another program
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());

        let to = Pubkey::new_unique();
        let to_account = AccountSharedData::new_ref(0, 0, &system_program::id());

        let signers = [from, to].iter().cloned().collect::<HashSet<_>>();
        let to_address = to.into();

        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&to, false, &to_account),
            &to_address,
            50,
            2,
            &sysvar::id(),
            &signers,
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::InvalidProgramId.into()));
    }

    #[test]
    fn test_create_data_populated() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        // Attempt to create system account in account with populated data
        let new_owner = Pubkey::new(&[9; 32]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());

        let populated_key = Pubkey::new_unique();
        let populated_account = AccountSharedData::from(Account {
            data: vec![0, 1, 2, 3],
            ..Account::default()
        })
        .into();

        let signers = [from, populated_key]
            .iter()
            .cloned()
            .collect::<HashSet<_>>();
        let populated_address = populated_key.into();

        let result = create_account(
            &KeyedAccount::new(&from, true, &from_account),
            &KeyedAccount::new(&populated_key, false, &populated_account),
            &populated_address,
            50,
            2,
            &new_owner,
            &signers,
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::AccountAlreadyInUse.into()));
    }

    #[test]
    fn test_create_from_account_is_nonce_fail() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let nonce = Pubkey::new_unique();
        let nonce_account = AccountSharedData::new_ref_data(
            42,
            &nonce::state::Versions::new(
                nonce::State::Initialized(nonce::state::Data::default()),
                true, // separate_domains
            ),
            &system_program::id(),
        )
        .unwrap();
        let from = KeyedAccount::new(&nonce, true, &nonce_account);
        let new = Pubkey::new_unique();

        let new_account = AccountSharedData::new_ref(0, 0, &system_program::id());

        let signers = [nonce, new].iter().cloned().collect::<HashSet<_>>();
        let new_address = new.into();
        let new_keyed_account = KeyedAccount::new(&new, false, &new_account);

        assert_eq!(
            create_account(
                &from,
                &new_keyed_account,
                &new_address,
                42,
                0,
                &Pubkey::new_unique(),
                &signers,
                &invoke_context,
            ),
            Err(InstructionError::InvalidArgument),
        );
    }

    #[test]
    fn test_assign() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let new_owner = Pubkey::new(&[9; 32]);
        let pubkey = Pubkey::new_unique();
        let mut account = AccountSharedData::new(100, 0, &system_program::id());

        assert_eq!(
            assign(
                &mut account,
                &pubkey.into(),
                &new_owner,
                &HashSet::new(),
                &invoke_context,
            ),
            Err(InstructionError::MissingRequiredSignature)
        );

        // no change, no signature needed
        assert_eq!(
            assign(
                &mut account,
                &pubkey.into(),
                &system_program::id(),
                &HashSet::new(),
                &invoke_context,
            ),
            Ok(())
        );

        let account = Rc::new(RefCell::new(account));
        assert_eq!(
            process_instruction(
                &bincode::serialize(&SystemInstruction::Assign { owner: new_owner }).unwrap(),
                &[(true, false, pubkey, account)],
            ),
            Ok(())
        );
    }

    #[test]
    fn test_assign_to_sysvar_with_feature() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let new_owner = sysvar::id();
        let from = Pubkey::new_unique();
        let mut from_account = AccountSharedData::new(100, 0, &system_program::id());

        assert_eq!(
            assign(
                &mut from_account,
                &from.into(),
                &new_owner,
                &[from].iter().cloned().collect::<HashSet<_>>(),
                &invoke_context,
            ),
            Ok(())
        );
    }

    #[test]
    fn test_assign_to_sysvar_without_feature() {
        let mut feature_set = FeatureSet::all_enabled();
        feature_set
            .active
            .remove(&feature_set::rent_for_sysvars::id());
        feature_set
            .inactive
            .insert(feature_set::rent_for_sysvars::id());
        let mut invoke_context = InvokeContext::new_mock(&[], &[]);
        invoke_context.feature_set = Arc::new(feature_set);
        let new_owner = sysvar::id();
        let from = Pubkey::new_unique();
        let mut from_account = AccountSharedData::new(100, 0, &system_program::id());

        assert_eq!(
            assign(
                &mut from_account,
                &from.into(),
                &new_owner,
                &[from].iter().cloned().collect::<HashSet<_>>(),
                &invoke_context,
            ),
            Err(SystemError::InvalidProgramId.into())
        );
    }

    #[test]
    fn test_process_bogus_instruction() {
        // Attempt to assign with no accounts
        let instruction = SystemInstruction::Assign {
            owner: Pubkey::new_unique(),
        };
        let data = serialize(&instruction).unwrap();
        let result = process_instruction(&data, &[]);
        assert_eq!(result, Err(InstructionError::NotEnoughAccountKeys));

        // Attempt to transfer with no destination
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &system_program::id());
        let instruction = SystemInstruction::Transfer { lamports: 0 };
        let data = serialize(&instruction).unwrap();
        let result = process_instruction(&data, &[(true, false, from, from_account)]);
        assert_eq!(result, Err(InstructionError::NotEnoughAccountKeys));
    }

    #[test]
    fn test_transfer_lamports() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref(100, 0, &Pubkey::new(&[2; 32])); // account owner should not matter
        let to = Pubkey::new(&[3; 32]);
        let to_account = AccountSharedData::new_ref(1, 0, &to); // account owner should not matter
        let from_keyed_account = KeyedAccount::new(&from, true, &from_account);
        let to_keyed_account = KeyedAccount::new(&to, false, &to_account);
        transfer(&from_keyed_account, &to_keyed_account, 50, &invoke_context).unwrap();
        let from_lamports = from_keyed_account.account.borrow().wens();
        let to_lamports = to_keyed_account.account.borrow().wens();
        assert_eq!(from_lamports, 50);
        assert_eq!(to_lamports, 51);

        // Attempt to move more lamports than remaining in from_account
        let from_keyed_account = KeyedAccount::new(&from, true, &from_account);
        let result = transfer(&from_keyed_account, &to_keyed_account, 100, &invoke_context);
        assert_eq!(result, Err(SystemError::ResultWithNegativeLamports.into()));
        assert_eq!(from_keyed_account.account.borrow().wens(), 50);
        assert_eq!(to_keyed_account.account.borrow().wens(), 51);

        // test signed transfer of zero
        assert!(transfer(&from_keyed_account, &to_keyed_account, 0, &invoke_context).is_ok());
        assert_eq!(from_keyed_account.account.borrow().wens(), 50);
        assert_eq!(to_keyed_account.account.borrow().wens(), 51);

        // test unsigned transfer of zero
        let from_keyed_account = KeyedAccount::new(&from, false, &from_account);

        assert_eq!(
            transfer(&from_keyed_account, &to_keyed_account, 0, &invoke_context),
            Err(InstructionError::MissingRequiredSignature)
        );
        assert_eq!(from_keyed_account.account.borrow().wens(), 50);
        assert_eq!(to_keyed_account.account.borrow().wens(), 51);
    }

    #[test]
    fn test_transfer_with_seed() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let base = Pubkey::new_unique();
        let base_account = AccountSharedData::new_ref(100, 0, &Pubkey::new(&[2; 32])); // account owner should not matter
        let from_base_keyed_account = KeyedAccount::new(&base, true, &base_account);
        let from_seed = "42";
        let from_owner = system_program::id();
        let from = Pubkey::create_with_seed(&base, from_seed, &from_owner).unwrap();
        let from_account = AccountSharedData::new_ref(100, 0, &Pubkey::new(&[2; 32])); // account owner should not matter
        let to = Pubkey::new(&[3; 32]);
        let to_account = AccountSharedData::new_ref(1, 0, &to); // account owner should not matter
        let from_keyed_account = KeyedAccount::new(&from, true, &from_account);
        let to_keyed_account = KeyedAccount::new(&to, false, &to_account);
        transfer_with_seed(
            &from_keyed_account,
            &from_base_keyed_account,
            from_seed,
            &from_owner,
            &to_keyed_account,
            50,
            &invoke_context,
        )
        .unwrap();
        let from_lamports = from_keyed_account.account.borrow().wens();
        let to_lamports = to_keyed_account.account.borrow().wens();
        assert_eq!(from_lamports, 50);
        assert_eq!(to_lamports, 51);

        // Attempt to move more lamports than remaining in from_account
        let from_keyed_account = KeyedAccount::new(&from, true, &from_account);
        let result = transfer_with_seed(
            &from_keyed_account,
            &from_base_keyed_account,
            from_seed,
            &from_owner,
            &to_keyed_account,
            100,
            &invoke_context,
        );
        assert_eq!(result, Err(SystemError::ResultWithNegativeLamports.into()));
        assert_eq!(from_keyed_account.account.borrow().wens(), 50);
        assert_eq!(to_keyed_account.account.borrow().wens(), 51);

        // test unsigned transfer of zero
        let from_keyed_account = KeyedAccount::new(&from, false, &from_account);
        assert!(transfer_with_seed(
            &from_keyed_account,
            &from_base_keyed_account,
            from_seed,
            &from_owner,
            &to_keyed_account,
            0,
            &invoke_context,
        )
        .is_ok());
        assert_eq!(from_keyed_account.account.borrow().wens(), 50);
        assert_eq!(to_keyed_account.account.borrow().wens(), 51);
    }

    #[test]
    fn test_transfer_lamports_from_nonce_account_fail() {
        let invoke_context = InvokeContext::new_mock(&[], &[]);
        let from = Pubkey::new_unique();
        let from_account = AccountSharedData::new_ref_data(
            100,
            &nonce::state::Versions::new(
                nonce::State::Initialized(nonce::state::Data {
                    authority: from,
                    ..nonce::state::Data::default()
                }),
                true, // separate_domains
            ),
            &system_program::id(),
        )
        .unwrap();
        assert_eq!(
            get_system_account_kind(&from_account.borrow()),
            Some(SystemAccountKind::Nonce)
        );

        let to = Pubkey::new(&[3; 32]);
        let to_account = AccountSharedData::new_ref(1, 0, &to); // account owner should not matter
        assert_eq!(
            transfer(
                &KeyedAccount::new(&from, true, &from_account),
                &KeyedAccount::new(&to, false, &to_account),
                50,
                &invoke_context,
            ),
            Err(InstructionError::InvalidArgument),
        )
    }

    #[test]
    fn test_allocate() {
        let (genesis_config, mint_keypair) = create_genesis_config(100);
        let bank = Bank::new_for_tests(&genesis_config);
        let bank_client = BankClient::new(bank);

        let alice_keypair = Keypair::new();
        let alice_pubkey = alice_keypair.pubkey();
        let seed = "seed";
        let owner = Pubkey::new_unique();
        let alice_with_seed = Pubkey::create_with_seed(&alice_pubkey, seed, &owner).unwrap();

        bank_client
            .transfer_and_confirm(50, &mint_keypair, &alice_pubkey)
            .unwrap();

        let allocate_with_seed = Message::new(
            &[system_instruction::allocate_with_seed(
                &alice_with_seed,
                &alice_pubkey,
                seed,
                2,
                &owner,
            )],
            Some(&alice_pubkey),
        );

        assert!(bank_client
            .send_and_confirm_message(&[&alice_keypair], allocate_with_seed)
            .is_ok());

        let allocate = system_instruction::allocate(&alice_pubkey, 2);

        assert!(bank_client
            .send_and_confirm_instruction(&alice_keypair, allocate)
            .is_ok());
    }

    fn with_create_zero_lamport<F>(callback: F)
    where
        F: Fn(&Bank),
    {
        sino_logger::setup();

        let alice_keypair = Keypair::new();
        let bob_keypair = Keypair::new();

        let alice_pubkey = alice_keypair.pubkey();
        let bob_pubkey = bob_keypair.pubkey();

        let program = Pubkey::new_unique();
        let collector = Pubkey::new_unique();

        let mint_lamports = 10000;
        let len1 = 123;
        let len2 = 456;

        // create initial bank and fund the alice account
        let (genesis_config, mint_keypair) = create_genesis_config(mint_lamports);
        let bank = Arc::new(Bank::new_for_tests(&genesis_config));
        let bank_client = BankClient::new_shared(&bank);
        bank_client
            .transfer_and_confirm(mint_lamports, &mint_keypair, &alice_pubkey)
            .unwrap();

        // create zero-lamports account to be cleaned
        let bank = Arc::new(Bank::new_from_parent(&bank, &collector, bank.slot() + 1));
        let bank_client = BankClient::new_shared(&bank);
        let ix = system_instruction::create_account(&alice_pubkey, &bob_pubkey, 0, len1, &program);
        let message = Message::new(&[ix], Some(&alice_keypair.pubkey()));
        let r = bank_client.send_and_confirm_message(&[&alice_keypair, &bob_keypair], message);
        assert!(r.is_ok());

        // transfer some to bogus pubkey just to make previous bank (=slot) really cleanable
        let bank = Arc::new(Bank::new_from_parent(&bank, &collector, bank.slot() + 1));
        let bank_client = BankClient::new_shared(&bank);
        bank_client
            .transfer_and_confirm(50, &alice_keypair, &Pubkey::new_unique())
            .unwrap();

        // super fun time; callback chooses to .clean_accounts(None) or not
        callback(&*bank);

        // create a normal account at the same pubkey as the zero-lamports account
        let bank = Arc::new(Bank::new_from_parent(&bank, &collector, bank.slot() + 1));
        let bank_client = BankClient::new_shared(&bank);
        let ix = system_instruction::create_account(&alice_pubkey, &bob_pubkey, 1, len2, &program);
        let message = Message::new(&[ix], Some(&alice_pubkey));
        let r = bank_client.send_and_confirm_message(&[&alice_keypair, &bob_keypair], message);
        assert!(r.is_ok());
    }

    #[test]
    fn test_create_zero_lamport_with_clean() {
        with_create_zero_lamport(|bank| {
            bank.freeze();
            bank.squash();
            bank.force_flush_accounts_cache();
            // do clean and assert that it actually did its job
            assert_eq!(3, bank.get_snapshot_storages(None).len());
            bank.clean_accounts(false, false, None);
            assert_eq!(2, bank.get_snapshot_storages(None).len());
        });
    }

    #[test]
    fn test_create_zero_lamport_without_clean() {
        with_create_zero_lamport(|_| {
            // just do nothing; this should behave identically with test_create_zero_lamport_with_clean
        });
    }

    #[test]
    fn test_assign_with_seed() {
        let (genesis_config, mint_keypair) = create_genesis_config(100);
        let bank = Bank::new_for_tests(&genesis_config);
        let bank_client = BankClient::new(bank);

        let alice_keypair = Keypair::new();
        let alice_pubkey = alice_keypair.pubkey();
        let seed = "seed";
        let owner = Pubkey::new_unique();
        let alice_with_seed = Pubkey::create_with_seed(&alice_pubkey, seed, &owner).unwrap();

        bank_client
            .transfer_and_confirm(50, &mint_keypair, &alice_pubkey)
            .unwrap();

        let assign_with_seed = Message::new(
            &[system_instruction::assign_with_seed(
                &alice_with_seed,
                &alice_pubkey,
                seed,
                &owner,
            )],
            Some(&alice_pubkey),
        );

        assert!(bank_client
            .send_and_confirm_message(&[&alice_keypair], assign_with_seed)
            .is_ok());
    }

    #[test]
    fn test_system_unsigned_transaction() {
        let (genesis_config, alice_keypair) = create_genesis_config(100);
        let alice_pubkey = alice_keypair.pubkey();
        let mallory_keypair = Keypair::new();
        let mallory_pubkey = mallory_keypair.pubkey();

        // Fund to account to bypass AccountNotFound error
        let bank = Bank::new_for_tests(&genesis_config);
        let bank_client = BankClient::new(bank);
        bank_client
            .transfer_and_confirm(50, &alice_keypair, &mallory_pubkey)
            .unwrap();

        // Erroneously sign transaction with recipient account key
        // No signature case is tested by bank `test_zero_signatures()`
        let account_metas = vec![
            AccountMeta::new(alice_pubkey, false),
            AccountMeta::new(mallory_pubkey, true),
        ];
        let malicious_instruction = Instruction::new_with_bincode(
            system_program::id(),
            &SystemInstruction::Transfer { lamports: 10 },
            account_metas,
        );
        assert_eq!(
            bank_client
                .send_and_confirm_instruction(&mallory_keypair, malicious_instruction)
                .unwrap_err()
                .unwrap(),
            TransactionError::InstructionError(0, InstructionError::MissingRequiredSignature)
        );
        assert_eq!(bank_client.get_balance(&alice_pubkey).unwrap(), 50);
        assert_eq!(bank_client.get_balance(&mallory_pubkey).unwrap(), 50);
    }

    fn process_nonce_instruction(instruction: &Instruction) -> Result<(), InstructionError> {
        let accounts = instruction.accounts.iter().map(|meta| {
            #[allow(deprecated)]
            if sysvar::recent_blockhashes::check_id(&meta.pubkey) {
                create_default_recent_blockhashes_account()
            } else if sysvar::rent::check_id(&meta.pubkey) {
                Rc::new(RefCell::new(account::create_account_shared_data_for_test(
                    &Rent::free(),
                )))
            } else {
                AccountSharedData::new_ref(0, 0, &Pubkey::new_unique())
            }
        });
        let keyed_accounts: Vec<_> = instruction
            .accounts
            .iter()
            .zip(accounts)
            .map(|(meta, account)| (meta.is_signer, meta.is_writable, meta.pubkey, account))
            .collect();
        process_instruction(&instruction.data, &keyed_accounts)
    }

    #[test]
    fn test_process_nonce_ix_no_acc_data_fail() {
        let none_address = Pubkey::new_unique();
        assert_eq!(
            process_nonce_instruction(&system_instruction::advance_nonce_account(
                &none_address,
                &none_address
            )),
            Err(InstructionError::InvalidAccountData),
        );
    }

    #[test]
    fn test_process_nonce_ix_no_keyed_accs_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::AdvanceNonceAccount).unwrap(),
                &[],
            ),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_process_nonce_ix_only_nonce_acc_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::AdvanceNonceAccount).unwrap(),
                &[(true, true, Pubkey::new_unique(), create_default_account())],
            ),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_process_nonce_ix_bad_recent_blockhash_state_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::AdvanceNonceAccount).unwrap(),
                &[
                    (true, true, Pubkey::new_unique(), create_default_account()),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_account(),
                    ),
                ],
            ),
            Err(InstructionError::InvalidArgument),
        );
    }

    #[test]
    fn test_process_nonce_ix_ok() {
        let nonce_address = Pubkey::new_unique();
        let nonce_account = Rc::new(nonce_account::create_account(
            1_000_000, /*separate_domains:*/ true,
        ));
        process_instruction(
            &serialize(&SystemInstruction::InitializeNonceAccount(nonce_address)).unwrap(),
            &[
                (true, true, nonce_address, nonce_account.clone()),
                (
                    false,
                    false,
                    #[allow(deprecated)]
                    sysvar::recent_blockhashes::id(),
                    create_default_recent_blockhashes_account(),
                ),
                (
                    false,
                    false,
                    sysvar::rent::id(),
                    create_default_rent_account(),
                ),
            ],
        )
        .unwrap();
        let blockhash = hash(&serialize(&0).unwrap());
        #[allow(deprecated)]
        let new_recent_blockhashes_account = Rc::new(RefCell::new(
            sdk::recent_blockhashes_account::create_account_with_data_for_test(
                vec![IterItem(0u64, &blockhash, 0); sysvar::recent_blockhashes::MAX_ENTRIES]
                    .into_iter(),
            ),
        ));
        #[allow(deprecated)]
        let blockhash_id = sysvar::recent_blockhashes::id();
        let keyed_accounts = [
            (true, true, nonce_address, nonce_account),
            (false, false, blockhash_id, new_recent_blockhashes_account),
        ];
        assert_eq!(
            mock_process_instruction(
                &system_program::id(),
                Vec::new(),
                &serialize(&SystemInstruction::AdvanceNonceAccount).unwrap(),
                &keyed_accounts,
                |first_instruction_account: usize,
                 instruction_data: &[u8],
                 invoke_context: &mut InvokeContext| {
                    invoke_context.blockhash = hash(&serialize(&0).unwrap());
                    super::process_instruction(
                        first_instruction_account,
                        instruction_data,
                        invoke_context,
                    )
                },
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_process_withdraw_ix_no_acc_data_fail() {
        let nonce_address = Pubkey::new_unique();
        assert_eq!(
            process_nonce_instruction(&system_instruction::withdraw_nonce_account(
                &nonce_address,
                &Pubkey::new_unique(),
                &nonce_address,
                1,
            )),
            Err(InstructionError::InvalidAccountData),
        );
    }

    #[test]
    fn test_process_withdraw_ix_no_keyed_accs_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::WithdrawNonceAccount(42)).unwrap(),
                &[],
            ),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_process_withdraw_ix_only_nonce_acc_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::WithdrawNonceAccount(42)).unwrap(),
                &[(true, false, Pubkey::default(), create_default_account())],
            ),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_process_withdraw_ix_bad_recent_blockhash_state_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::WithdrawNonceAccount(42)).unwrap(),
                &[
                    (true, false, Pubkey::default(), create_default_account()),
                    (false, false, Pubkey::default(), create_default_account()),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_account()
                    ),
                ],
            ),
            Err(InstructionError::InvalidArgument),
        );
    }

    #[test]
    fn test_process_withdraw_ix_bad_rent_state_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::WithdrawNonceAccount(42)).unwrap(),
                &[
                    (
                        true,
                        false,
                        Pubkey::default(),
                        Rc::new(nonce_account::create_account(
                            1_000_000, /*separate_domains:*/ true
                        )),
                    ),
                    (true, false, Pubkey::default(), create_default_account()),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_recent_blockhashes_account(),
                    ),
                    (false, false, sysvar::rent::id(), create_default_account()),
                ],
            ),
            Err(InstructionError::InvalidArgument),
        );
    }

    #[test]
    fn test_process_withdraw_ix_ok() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::WithdrawNonceAccount(42)).unwrap(),
                &[
                    (
                        true,
                        true,
                        Pubkey::new_unique(),
                        Rc::new(nonce_account::create_account(
                            1_000_000, /*separate_domains:*/ true
                        )),
                    ),
                    (true, false, Pubkey::default(), create_default_account()),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_recent_blockhashes_account(),
                    ),
                    (
                        false,
                        false,
                        sysvar::rent::id(),
                        create_default_rent_account()
                    ),
                ],
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_process_initialize_ix_no_keyed_accs_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::InitializeNonceAccount(Pubkey::default())).unwrap(),
                &[],
            ),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_process_initialize_ix_only_nonce_acc_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::InitializeNonceAccount(Pubkey::default())).unwrap(),
                &[(
                    true,
                    false,
                    Pubkey::default(),
                    Rc::new(nonce_account::create_account(
                        1_000_000, /*separate_domains:*/ true
                    )),
                )],
            ),
            Err(InstructionError::NotEnoughAccountKeys),
        );
    }

    #[test]
    fn test_process_initialize_bad_recent_blockhash_state_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::InitializeNonceAccount(Pubkey::default())).unwrap(),
                &[
                    (
                        true,
                        false,
                        Pubkey::default(),
                        Rc::new(nonce_account::create_account(
                            1_000_000, /*separate_domains:*/ true
                        )),
                    ),
                    (
                        true,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_account()
                    ),
                ],
            ),
            Err(InstructionError::InvalidArgument),
        );
    }

    #[test]
    fn test_process_initialize_ix_bad_rent_state_fail() {
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::InitializeNonceAccount(Pubkey::default())).unwrap(),
                &[
                    (
                        true,
                        false,
                        Pubkey::default(),
                        Rc::new(nonce_account::create_account(
                            1_000_000, /*separate_domains:*/ true
                        )),
                    ),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_recent_blockhashes_account(),
                    ),
                    (false, false, sysvar::rent::id(), create_default_account()),
                ],
            ),
            Err(InstructionError::InvalidArgument),
        );
    }

    #[test]
    fn test_process_initialize_ix_ok() {
        let nonce_address = Pubkey::new_unique();
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::InitializeNonceAccount(nonce_address)).unwrap(),
                &[
                    (
                        true,
                        true,
                        nonce_address,
                        Rc::new(nonce_account::create_account(
                            1_000_000, /*separate_domains:*/ true
                        )),
                    ),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        create_default_recent_blockhashes_account(),
                    ),
                    (
                        false,
                        false,
                        sysvar::rent::id(),
                        create_default_rent_account()
                    ),
                ],
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_process_authorize_ix_ok() {
        let nonce_address = Pubkey::new_unique();
        let nonce_account = Rc::new(nonce_account::create_account(
            1_000_000, /*separate_domains:*/ true,
        ));
        process_instruction(
            &serialize(&SystemInstruction::InitializeNonceAccount(nonce_address)).unwrap(),
            &[
                (true, true, nonce_address, nonce_account.clone()),
                (
                    false,
                    false,
                    #[allow(deprecated)]
                    sysvar::recent_blockhashes::id(),
                    create_default_recent_blockhashes_account(),
                ),
                (
                    false,
                    false,
                    sysvar::rent::id(),
                    create_default_rent_account(),
                ),
            ],
        )
        .unwrap();
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::AuthorizeNonceAccount(nonce_address)).unwrap(),
                &[(true, true, nonce_address, nonce_account)],
            ),
            Ok(()),
        );
    }

    #[test]
    fn test_process_authorize_bad_account_data_fail() {
        let nonce_address = Pubkey::new_unique();
        assert_eq!(
            process_nonce_instruction(&system_instruction::authorize_nonce_account(
                &nonce_address,
                &Pubkey::new_unique(),
                &nonce_address,
            )),
            Err(InstructionError::InvalidAccountData),
        );
    }

    #[test]
    fn test_get_system_account_kind_system_ok() {
        let system_account = AccountSharedData::default();
        assert_eq!(
            get_system_account_kind(&system_account),
            Some(SystemAccountKind::System)
        );
    }

    #[test]
    fn test_get_system_account_kind_nonce_ok() {
        let nonce_account = AccountSharedData::new_data(
            42,
            &nonce::state::Versions::new(
                nonce::State::Initialized(nonce::state::Data::default()),
                true, // separate_domains
            ),
            &system_program::id(),
        )
        .unwrap();
        assert_eq!(
            get_system_account_kind(&nonce_account),
            Some(SystemAccountKind::Nonce)
        );
    }

    #[test]
    fn test_get_system_account_kind_uninitialized_nonce_account_fail() {
        assert_eq!(
            get_system_account_kind(
                &nonce_account::create_account(42, /*separate_domains:*/ true).borrow()
            ),
            None
        );
    }

    #[test]
    fn test_get_system_account_kind_system_owner_nonzero_nonnonce_data_fail() {
        let other_data_account =
            AccountSharedData::new_data(42, b"other", &Pubkey::default()).unwrap();
        assert_eq!(get_system_account_kind(&other_data_account), None);
    }

    #[test]
    fn test_get_system_account_kind_nonsystem_owner_with_nonce_data_fail() {
        let nonce_account = AccountSharedData::new_data(
            42,
            &nonce::state::Versions::new(
                nonce::State::Initialized(nonce::state::Data::default()),
                true, // separate_domains
            ),
            &Pubkey::new_unique(),
        )
        .unwrap();
        assert_eq!(get_system_account_kind(&nonce_account), None);
    }

    #[test]
    fn test_nonce_initialize_with_empty_recent_blockhashes_fail() {
        let nonce_address = Pubkey::new_unique();
        let nonce_account = Rc::new(nonce_account::create_account(
            1_000_000, /*separate_domains:*/ true,
        ));
        #[allow(deprecated)]
        let new_recent_blockhashes_account = Rc::new(RefCell::new(
            sdk::recent_blockhashes_account::create_account_with_data_for_test(
                vec![].into_iter(),
            ),
        ));
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::InitializeNonceAccount(nonce_address)).unwrap(),
                &[
                    (true, true, nonce_address, nonce_account),
                    (
                        false,
                        false,
                        #[allow(deprecated)]
                        sysvar::recent_blockhashes::id(),
                        new_recent_blockhashes_account,
                    ),
                    (
                        false,
                        false,
                        sysvar::rent::id(),
                        create_default_rent_account()
                    ),
                ],
            ),
            Err(NonceError::NoRecentBlockhashes.into())
        );
    }

    #[test]
    fn test_nonce_advance_with_empty_recent_blockhashes_fail() {
        let nonce_address = Pubkey::new_unique();
        let nonce_account = Rc::new(nonce_account::create_account(
            1_000_000, /*separate_domains:*/ true,
        ));
        process_instruction(
            &serialize(&SystemInstruction::InitializeNonceAccount(nonce_address)).unwrap(),
            &[
                (true, true, nonce_address, nonce_account.clone()),
                (
                    false,
                    false,
                    #[allow(deprecated)]
                    sysvar::recent_blockhashes::id(),
                    create_default_recent_blockhashes_account(),
                ),
                (
                    false,
                    false,
                    sysvar::rent::id(),
                    create_default_rent_account(),
                ),
            ],
        )
        .unwrap();
        #[allow(deprecated)]
        let new_recent_blockhashes_account = Rc::new(RefCell::new(
            sdk::recent_blockhashes_account::create_account_with_data_for_test(
                vec![].into_iter(),
            ),
        ));
        #[allow(deprecated)]
        let blockhash_id = sysvar::recent_blockhashes::id();
        let keyed_accounts = [
            (true, false, nonce_address, nonce_account),
            (false, false, blockhash_id, new_recent_blockhashes_account),
        ];
        assert_eq!(
            mock_process_instruction(
                &system_program::id(),
                Vec::new(),
                &serialize(&SystemInstruction::AdvanceNonceAccount).unwrap(),
                &keyed_accounts,
                |first_instruction_account: usize,
                 instruction_data: &[u8],
                 invoke_context: &mut InvokeContext| {
                    invoke_context.blockhash = hash(&serialize(&0).unwrap());
                    super::process_instruction(
                        first_instruction_account,
                        instruction_data,
                        invoke_context,
                    )
                },
            ),
            Err(NonceError::NoRecentBlockhashes.into()),
        );
    }

    #[test]
    fn test_nonce_account_upgrade_check_owner() {
        let nonce_address = Pubkey::new_unique();
        let versions = NonceVersions::Legacy(Box::new(NonceState::Uninitialized));
        let nonce_account = AccountSharedData::new_data(
            1_000_000,             // lamports
            &versions,             // state
            &Pubkey::new_unique(), // owner
        )
        .unwrap();
        let keyed_accounts = vec![(
            false,
            true,
            nonce_address,
            Rc::new(RefCell::new(nonce_account.clone())),
        )];
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::UpgradeNonceAccount).unwrap(),
                &keyed_accounts,
            ),
            Err(InstructionError::InvalidAccountOwner)
        );
        assert_eq!(*keyed_accounts[0].3.borrow(), nonce_account);
    }

    fn new_nonce_account(versions: NonceVersions) -> AccountSharedData {
        let nonce_account = AccountSharedData::new_data(
            1_000_000,             // lamports
            &versions,             // state
            &system_program::id(), // owner
        )
        .unwrap();
        assert_eq!(
            nonce_account.deserialize_data::<NonceVersions>().unwrap(),
            versions
        );
        nonce_account
    }

    #[test]
    fn test_nonce_account_upgrade() {
        let nonce_address = Pubkey::new_unique();
        let versions = NonceVersions::Legacy(Box::new(NonceState::Uninitialized));
        let nonce_account = new_nonce_account(versions);
        let keyed_accounts = vec![(
            false,
            true,
            nonce_address,
            Rc::new(RefCell::new(nonce_account.clone())),
        )];
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::UpgradeNonceAccount).unwrap(),
                &keyed_accounts,
            ),
            Err(InstructionError::InvalidArgument)
        );
        assert_eq!(*keyed_accounts[0].3.borrow(), nonce_account);
        let versions = NonceVersions::Current(Box::new(NonceState::Uninitialized));
        let nonce_account = new_nonce_account(versions);
        let keyed_accounts = vec![(
            false,
            true,
            nonce_address,
            Rc::new(RefCell::new(nonce_account.clone())),
        )];
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::UpgradeNonceAccount).unwrap(),
                &keyed_accounts,
            ),
            Err(InstructionError::InvalidArgument)
        );
        assert_eq!(*keyed_accounts[0].3.borrow(), nonce_account);
        let blockhash = hashv(&[&[171u8; 32]]);
        let durable_nonce =
            DurableNonce::from_blockhash(&blockhash, /*separate_domains:*/ false);
        let data = NonceData {
            authority: Pubkey::new_unique(),
            durable_nonce,
            fee_calculator: FeeCalculator {
                wens_per_signature: 2718,
            },
        };
        let versions = NonceVersions::Legacy(Box::new(NonceState::Initialized(data.clone())));
        let nonce_account = new_nonce_account(versions);
        let keyed_accounts = vec![(
            false,
            false, // Should fail!
            nonce_address,
            Rc::new(RefCell::new(nonce_account.clone())),
        )];
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::UpgradeNonceAccount).unwrap(),
                &keyed_accounts,
            ),
            Err(InstructionError::InvalidArgument)
        );
        assert_eq!(*keyed_accounts[0].3.borrow(), nonce_account);
        let keyed_accounts = vec![(
            false,
            true,
            nonce_address,
            Rc::new(RefCell::new(nonce_account)),
        )];
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::UpgradeNonceAccount).unwrap(),
                &keyed_accounts,
            ),
            Ok(()),
        );
        let durable_nonce =
            DurableNonce::from_blockhash(&blockhash, /*separate_domains:*/ true);
        assert_ne!(data.durable_nonce, durable_nonce);
        let data = NonceData {
            durable_nonce,
            ..data
        };
        let upgraded_nonce_account = new_nonce_account(NonceVersions::Current(Box::new(
            NonceState::Initialized(data),
        )));
        assert_eq!(*keyed_accounts[0].3.borrow(), upgraded_nonce_account);
        assert_eq!(
            process_instruction(
                &serialize(&SystemInstruction::UpgradeNonceAccount).unwrap(),
                &keyed_accounts,
            ),
            Err(InstructionError::InvalidArgument)
        );
        assert_eq!(*keyed_accounts[0].3.borrow(), upgraded_nonce_account);
    }
}
