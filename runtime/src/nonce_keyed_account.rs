use {
    program_runtime::{ic_msg, invoke_context::InvokeContext},
    sdk::{
        account::{ReadableAccount, WritableAccount},
        account_utils::State as AccountUtilsState,
        feature_set::{self, nonce_must_be_writable},
        instruction::{checked_add, InstructionError},
        keyed_account::KeyedAccount,
        nonce::{
            self,
            state::{DurableNonce, Versions},
            State,
        },
        pubkey::Pubkey,
        system_instruction::{nonce_to_instruction_error, NonceError},
        sysvar::rent::Rent,
    },
    std::collections::HashSet,
};

pub trait NonceKeyedAccount {
    fn advance_nonce_account(
        &self,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
    fn withdraw_nonce_account(
        &self,
        wens: u64,
        to: &KeyedAccount,
        rent: &Rent,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
    fn initialize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        rent: &Rent,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
    fn authorize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError>;
}

fn get_durable_nonce(invoke_context: &InvokeContext) -> (DurableNonce, /*separate_domains:*/ bool) {
    let separate_nonce_from_blockhash = invoke_context
        .feature_set
        .is_active(&feature_set::separate_nonce_from_blockhash::id());
    let durable_nonce =
        DurableNonce::from_blockhash(&invoke_context.blockhash, separate_nonce_from_blockhash);
    (durable_nonce, separate_nonce_from_blockhash)
}

impl<'a> NonceKeyedAccount for KeyedAccount<'a> {
    fn advance_nonce_account(
        &self,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Advance nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        let state = AccountUtilsState::<Versions>::state(self)?;
        match state.state() {
            State::Initialized(data) => {
                if !signers.contains(&data.authority) {
                    ic_msg!(
                        invoke_context,
                        "Advance nonce account: Account {} must be a signer",
                        data.authority
                    );
                    return Err(InstructionError::MissingRequiredSignature);
                }
                let (next_durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
                if data.durable_nonce == next_durable_nonce {
                    ic_msg!(
                        invoke_context,
                        "Advance nonce account: nonce can only advance once per slot"
                    );
                    return Err(nonce_to_instruction_error(
                        NonceError::NotExpired,
                        merge_nonce_error_into_system_error,
                    ));
                }

                let new_data = nonce::state::Data::new(
                    data.authority,
                    next_durable_nonce,
                    invoke_context.wens_per_signature,
                );
                self.set_state(&Versions::new(
                    State::Initialized(new_data),
                    separate_domains,
                ))
            }
            State::Uninitialized => {
                ic_msg!(
                    invoke_context,
                    "Advance nonce account: Account {} state is invalid",
                    self.unsigned_key()
                );
                Err(nonce_to_instruction_error(
                    NonceError::BadAccountState,
                    merge_nonce_error_into_system_error,
                ))
            }
        }
    }

    fn withdraw_nonce_account(
        &self,
        wens: u64,
        to: &KeyedAccount,
        rent: &Rent,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Withdraw nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        let signer = match AccountUtilsState::<Versions>::state(self)?.state() {
            State::Uninitialized => {
                if wens > self.wens()? {
                    ic_msg!(
                        invoke_context,
                        "Withdraw nonce account: insufficient wens {}, need {}",
                        self.wens()?,
                        wens,
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                *self.unsigned_key()
            }
            State::Initialized(ref data) => {
                if wens == self.wens()? {
                    let (durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
                    if data.durable_nonce == durable_nonce {
                        ic_msg!(
                            invoke_context,
                            "Withdraw nonce account: nonce can only advance once per slot"
                        );
                        return Err(nonce_to_instruction_error(
                            NonceError::NotExpired,
                            merge_nonce_error_into_system_error,
                        ));
                    }
                    self.set_state(&Versions::new(State::Uninitialized, separate_domains))?;
                } else {
                    let min_balance = rent.minimum_balance(self.data_len()?);
                    let amount = checked_add(wens, min_balance)?;
                    if amount > self.wens()? {
                        ic_msg!(
                            invoke_context,
                            "Withdraw nonce account: insufficient wens {}, need {}",
                            self.wens()?,
                            amount,
                        );
                        return Err(InstructionError::InsufficientFunds);
                    }
                }
                data.authority
            }
        };

        if !signers.contains(&signer) {
            ic_msg!(
                invoke_context,
                "Withdraw nonce account: Account {} must sign",
                signer
            );
            return Err(InstructionError::MissingRequiredSignature);
        }

        let nonce_balance = self.try_account_ref_mut()?.wens();
        self.try_account_ref_mut()?.set_wens(
            nonce_balance
                .checked_sub(wens)
                .ok_or(InstructionError::ArithmeticOverflow)?,
        );
        let to_balance = to.try_account_ref_mut()?.wens();
        to.try_account_ref_mut()?.set_wens(
            to_balance
                .checked_add(wens)
                .ok_or(InstructionError::ArithmeticOverflow)?,
        );

        Ok(())
    }

    fn initialize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        rent: &Rent,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Initialize nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        match AccountUtilsState::<Versions>::state(self)?.state() {
            State::Uninitialized => {
                let min_balance = rent.minimum_balance(self.data_len()?);
                if self.wens()? < min_balance {
                    ic_msg!(
                        invoke_context,
                        "Initialize nonce account: insufficient wens {}, need {}",
                        self.wens()?,
                        min_balance
                    );
                    return Err(InstructionError::InsufficientFunds);
                }
                let (durable_nonce, separate_domains) = get_durable_nonce(invoke_context);
                let data = nonce::state::Data::new(
                    *nonce_authority,
                    durable_nonce,
                    invoke_context.wens_per_signature,
                );
                let state = State::Initialized(data);
                self.set_state(&Versions::new(state, separate_domains))
            }
            State::Initialized(_) => {
                ic_msg!(
                    invoke_context,
                    "Initialize nonce account: Account {} state is invalid",
                    self.unsigned_key()
                );
                Err(nonce_to_instruction_error(
                    NonceError::BadAccountState,
                    merge_nonce_error_into_system_error,
                ))
            }
        }
    }

    fn authorize_nonce_account(
        &self,
        nonce_authority: &Pubkey,
        signers: &HashSet<Pubkey>,
        invoke_context: &InvokeContext,
    ) -> Result<(), InstructionError> {
        let merge_nonce_error_into_system_error = invoke_context
            .feature_set
            .is_active(&feature_set::merge_nonce_error_into_system_error::id());

        if invoke_context
            .feature_set
            .is_active(&nonce_must_be_writable::id())
            && !self.is_writable()
        {
            ic_msg!(
                invoke_context,
                "Authorize nonce account: Account {} must be writeable",
                self.unsigned_key()
            );
            return Err(InstructionError::InvalidArgument);
        }

        let state = AccountUtilsState::<Versions>::state(self)?;
        let separate_domains = state.separate_domains();
        match state.state() {
            State::Initialized(data) => {
                if !signers.contains(&data.authority) {
                    ic_msg!(
                        invoke_context,
                        "Authorize nonce account: Account {} must sign",
                        data.authority
                    );
                    return Err(InstructionError::MissingRequiredSignature);
                }
                let new_data = nonce::state::Data::new(
                    *nonce_authority,
                    data.durable_nonce,
                    data.get_wens_per_signature(),
                );
                self.set_state(&Versions::new(
                    State::Initialized(new_data),
                    separate_domains,
                ))
            }
            State::Uninitialized => {
                ic_msg!(
                    invoke_context,
                    "Authorize nonce account: Account {} state is invalid",
                    self.unsigned_key()
                );
                Err(nonce_to_instruction_error(
                    NonceError::BadAccountState,
                    merge_nonce_error_into_system_error,
                ))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use {
        super::*,
        assert_matches::assert_matches,
        program_runtime::invoke_context::InvokeContext,
        sdk::{
            account::ReadableAccount,
            account_utils::State as AccountUtilsState,
            hash::{hash, Hash},
            keyed_account::KeyedAccount,
            nonce::{self, State},
            nonce_account::{create_account, verify_nonce_account},
            system_instruction::SystemError,
        },
    };

    fn with_test_keyed_account<F>(wens: u64, signer: bool, f: F)
    where
        F: Fn(&KeyedAccount),
    {
        let pubkey = Pubkey::new_unique();
        let account = create_account(wens, /*separate_domains:*/ true);
        let keyed_account = KeyedAccount::new(&pubkey, signer, &account);
        f(&keyed_account)
    }

    fn create_test_blockhash(seed: usize) -> (Hash, u64) {
        (
            hash(&bincode::serialize(&seed).unwrap()),
            (seed as u64).saturating_mul(100),
        )
    }

    fn create_invoke_context_with_blockhash<'a>(seed: usize) -> InvokeContext<'a> {
        let mut invoke_context = InvokeContext::new_mock(&[], &[]);
        let (blockhash, wens_per_signature) = create_test_blockhash(seed);
        invoke_context.blockhash = blockhash;
        invoke_context.wens_per_signature = wens_per_signature;
        invoke_context
    }

    #[test]
    fn default_is_uninitialized() {
        assert_eq!(State::default(), State::Uninitialized)
    }

    #[test]
    fn keyed_account_expected_behavior() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |keyed_account| {
            let data = nonce::state::Data {
                authority: *keyed_account.unsigned_key(),
                ..nonce::state::Data::default()
            };
            let mut signers = HashSet::new();
            signers.insert(*keyed_account.signer_key().unwrap());
            let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
            // New is in Uninitialzed state
            assert_eq!(versions.state(), &State::Uninitialized);
            let invoke_context = create_invoke_context_with_blockhash(95);
            let authorized = keyed_account.unsigned_key();
            keyed_account
                .initialize_nonce_account(authorized, &rent, &invoke_context)
                .unwrap();
            let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
            let data = nonce::state::Data::new(
                data.authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            // First nonce instruction drives state from Uninitialized to Initialized
            assert_eq!(versions.state(), &State::Initialized(data.clone()));
            let invoke_context = create_invoke_context_with_blockhash(63);
            keyed_account
                .advance_nonce_account(&signers, &invoke_context)
                .unwrap();
            let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
            let data = nonce::state::Data::new(
                data.authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            // Second nonce instruction consumes and replaces stored nonce
            assert_eq!(versions.state(), &State::Initialized(data.clone()));
            let invoke_context = create_invoke_context_with_blockhash(31);
            keyed_account
                .advance_nonce_account(&signers, &invoke_context)
                .unwrap();
            let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
            let data = nonce::state::Data::new(
                data.authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            // Third nonce instruction for fun and profit
            assert_eq!(versions.state(), &State::Initialized(data));
            with_test_keyed_account(42, false, |to_keyed| {
                let invoke_context = create_invoke_context_with_blockhash(0);
                let withdraw_wens = keyed_account.account.borrow().wens();
                let expect_nonce_wens =
                    keyed_account.account.borrow().wens() - withdraw_wens;
                let expect_to_wens = to_keyed.account.borrow().wens() + withdraw_wens;
                keyed_account
                    .withdraw_nonce_account(
                        withdraw_wens,
                        to_keyed,
                        &rent,
                        &signers,
                        &invoke_context,
                    )
                    .unwrap();
                // Empties Account balance
                assert_eq!(
                    keyed_account.account.borrow().wens(),
                    expect_nonce_wens
                );
                // Account balance goes to `to`
                assert_eq!(to_keyed.account.borrow().wens(), expect_to_wens);
                let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
                // Empty balance deinitializes data
                assert_eq!(versions.state(), &State::Uninitialized);
            })
        })
    }

    #[test]
    fn nonce_inx_initialized_account_not_signer_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_account| {
            let invoke_context = create_invoke_context_with_blockhash(31);
            let authority = *nonce_account.unsigned_key();
            nonce_account
                .initialize_nonce_account(&authority, &rent, &invoke_context)
                .unwrap();
            let pubkey = *nonce_account.account.borrow().owner();
            let nonce_account = KeyedAccount::new(&pubkey, false, nonce_account.account);
            let versions = AccountUtilsState::<Versions>::state(&nonce_account).unwrap();
            let data = nonce::state::Data::new(
                authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            assert_eq!(versions.state(), &State::Initialized(data));
            let signers = HashSet::new();
            let invoke_context = create_invoke_context_with_blockhash(0);

            let result = nonce_account.advance_nonce_account(&signers, &invoke_context);
            assert_eq!(result, Err(InstructionError::MissingRequiredSignature),);
        })
    }

    #[test]
    fn nonce_inx_too_early_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |keyed_account| {
            let mut signers = HashSet::new();
            signers.insert(*keyed_account.signer_key().unwrap());
            let invoke_context = create_invoke_context_with_blockhash(63);
            let authorized = *keyed_account.unsigned_key();
            keyed_account
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            let result = keyed_account.advance_nonce_account(&signers, &invoke_context);
            assert_eq!(result, Err(SystemError::NonceBlockhashNotExpired.into()));
        })
    }

    #[test]
    fn nonce_inx_uninitialized_account_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |keyed_account| {
            let mut signers = HashSet::new();
            signers.insert(*keyed_account.signer_key().unwrap());
            let invoke_context = create_invoke_context_with_blockhash(63);
            let result = keyed_account.advance_nonce_account(&signers, &invoke_context);
            assert_eq!(result, Err(InstructionError::InvalidAccountData));
        })
    }

    #[test]
    fn nonce_inx_independent_nonce_authority_ok() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_account| {
            with_test_keyed_account(42, true, |nonce_authority| {
                let mut signers = HashSet::new();
                signers.insert(*nonce_account.signer_key().unwrap());
                let invoke_context = create_invoke_context_with_blockhash(63);
                let authorized = *nonce_authority.unsigned_key();
                nonce_account
                    .initialize_nonce_account(&authorized, &rent, &invoke_context)
                    .unwrap();
                let mut signers = HashSet::new();
                signers.insert(*nonce_authority.signer_key().unwrap());
                let invoke_context = create_invoke_context_with_blockhash(31);
                let result = nonce_account.advance_nonce_account(&signers, &invoke_context);
                assert_eq!(result, Ok(()));
            });
        });
    }

    #[test]
    fn nonce_inx_no_nonce_authority_sig_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_account| {
            with_test_keyed_account(42, false, |nonce_authority| {
                let mut signers = HashSet::new();
                signers.insert(*nonce_account.signer_key().unwrap());
                let invoke_context = create_invoke_context_with_blockhash(63);
                let authorized = *nonce_authority.unsigned_key();
                nonce_account
                    .initialize_nonce_account(&authorized, &rent, &invoke_context)
                    .unwrap();
                let result = nonce_account.advance_nonce_account(&signers, &invoke_context);
                assert_eq!(result, Err(InstructionError::MissingRequiredSignature),);
            });
        });
    }

    #[test]
    fn withdraw_inx_unintialized_acc_ok() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let verions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
            assert_eq!(verions.state(), &State::Uninitialized);
            with_test_keyed_account(42, false, |to_keyed| {
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let invoke_context = create_invoke_context_with_blockhash(0);
                let withdraw_wens = nonce_keyed.account.borrow().wens();
                let expect_nonce_wens =
                    nonce_keyed.account.borrow().wens() - withdraw_wens;
                let expect_to_wens = to_keyed.account.borrow().wens() + withdraw_wens;
                nonce_keyed
                    .withdraw_nonce_account(
                        withdraw_wens,
                        to_keyed,
                        &rent,
                        &signers,
                        &invoke_context,
                    )
                    .unwrap();
                let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
                // Withdraw instruction...
                // Deinitializes Account state
                assert_eq!(versions.state(), &State::Uninitialized);
                // Empties Account balance
                assert_eq!(
                    nonce_keyed.account.borrow().wens(),
                    expect_nonce_wens
                );
                // Account balance goes to `to`
                assert_eq!(to_keyed.account.borrow().wens(), expect_to_wens);
            })
        })
    }

    #[test]
    fn withdraw_inx_unintialized_acc_unsigned_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, false, |nonce_keyed| {
            let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
            assert_eq!(versions.state(), &State::Uninitialized);
            with_test_keyed_account(42, false, |to_keyed| {
                let signers = HashSet::new();
                let invoke_context = create_invoke_context_with_blockhash(0);
                let wens = nonce_keyed.account.borrow().wens();
                let result = nonce_keyed.withdraw_nonce_account(
                    wens,
                    to_keyed,
                    &rent,
                    &signers,
                    &invoke_context,
                );
                assert_eq!(result, Err(InstructionError::MissingRequiredSignature),);
            })
        })
    }

    #[test]
    fn withdraw_inx_unintialized_acc_insuff_funds_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
            assert_eq!(versions.state(), &State::Uninitialized);
            with_test_keyed_account(42, false, |to_keyed| {
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let invoke_context = create_invoke_context_with_blockhash(0);
                let wens = nonce_keyed.account.borrow().wens() + 1;
                let result = nonce_keyed.withdraw_nonce_account(
                    wens,
                    to_keyed,
                    &rent,
                    &signers,
                    &invoke_context,
                );
                assert_eq!(result, Err(InstructionError::InsufficientFunds));
            })
        })
    }

    #[test]
    fn withdraw_inx_uninitialized_acc_two_withdraws_ok() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            with_test_keyed_account(42, false, |to_keyed| {
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let invoke_context = create_invoke_context_with_blockhash(0);
                let withdraw_wens = nonce_keyed.account.borrow().wens() / 2;
                let nonce_expect_wens =
                    nonce_keyed.account.borrow().wens() - withdraw_wens;
                let to_expect_wens = to_keyed.account.borrow().wens() + withdraw_wens;
                nonce_keyed
                    .withdraw_nonce_account(
                        withdraw_wens,
                        to_keyed,
                        &rent,
                        &signers,
                        &invoke_context,
                    )
                    .unwrap();
                let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
                assert_eq!(versions.state(), &State::Uninitialized);
                assert_eq!(
                    nonce_keyed.account.borrow().wens(),
                    nonce_expect_wens
                );
                assert_eq!(to_keyed.account.borrow().wens(), to_expect_wens);
                let withdraw_wens = nonce_keyed.account.borrow().wens();
                let nonce_expect_wens =
                    nonce_keyed.account.borrow().wens() - withdraw_wens;
                let to_expect_wens = to_keyed.account.borrow().wens() + withdraw_wens;
                nonce_keyed
                    .withdraw_nonce_account(
                        withdraw_wens,
                        to_keyed,
                        &rent,
                        &signers,
                        &invoke_context,
                    )
                    .unwrap();
                let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
                assert_eq!(versions.state(), &State::Uninitialized);
                assert_eq!(
                    nonce_keyed.account.borrow().wens(),
                    nonce_expect_wens
                );
                assert_eq!(to_keyed.account.borrow().wens(), to_expect_wens);
            })
        })
    }

    #[test]
    fn withdraw_inx_initialized_acc_two_withdraws_ok() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let mut signers = HashSet::new();
            signers.insert(*nonce_keyed.signer_key().unwrap());
            let invoke_context = create_invoke_context_with_blockhash(31);
            let authority = *nonce_keyed.unsigned_key();
            nonce_keyed
                .initialize_nonce_account(&authority, &rent, &invoke_context)
                .unwrap();
            let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
            let data = nonce::state::Data::new(
                authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            assert_eq!(versions.state(), &State::Initialized(data.clone()));
            with_test_keyed_account(42, false, |to_keyed| {
                let withdraw_wens = nonce_keyed.account.borrow().wens() - min_wens;
                let nonce_expect_wens =
                    nonce_keyed.account.borrow().wens() - withdraw_wens;
                let to_expect_wens = to_keyed.account.borrow().wens() + withdraw_wens;
                nonce_keyed
                    .withdraw_nonce_account(
                        withdraw_wens,
                        to_keyed,
                        &rent,
                        &signers,
                        &invoke_context,
                    )
                    .unwrap();
                let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
                let data = nonce::state::Data::new(
                    data.authority,
                    get_durable_nonce(&invoke_context).0,
                    invoke_context.wens_per_signature,
                );
                assert_eq!(versions.state(), &State::Initialized(data));
                assert_eq!(
                    nonce_keyed.account.borrow().wens(),
                    nonce_expect_wens
                );
                assert_eq!(to_keyed.account.borrow().wens(), to_expect_wens);
                let invoke_context = create_invoke_context_with_blockhash(0);
                let withdraw_wens = nonce_keyed.account.borrow().wens();
                let nonce_expect_wens =
                    nonce_keyed.account.borrow().wens() - withdraw_wens;
                let to_expect_wens = to_keyed.account.borrow().wens() + withdraw_wens;
                nonce_keyed
                    .withdraw_nonce_account(
                        withdraw_wens,
                        to_keyed,
                        &rent,
                        &signers,
                        &invoke_context,
                    )
                    .unwrap();
                let versions = AccountUtilsState::<Versions>::state(nonce_keyed).unwrap();
                assert_eq!(versions.state(), &State::Uninitialized);
                assert_eq!(
                    nonce_keyed.account.borrow().wens(),
                    nonce_expect_wens
                );
                assert_eq!(to_keyed.account.borrow().wens(), to_expect_wens);
            })
        })
    }

    #[test]
    fn withdraw_inx_initialized_acc_nonce_too_early_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let invoke_context = create_invoke_context_with_blockhash(0);
            let authorized = *nonce_keyed.unsigned_key();
            nonce_keyed
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            with_test_keyed_account(42, false, |to_keyed| {
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let withdraw_wens = nonce_keyed.account.borrow().wens();
                let result = nonce_keyed.withdraw_nonce_account(
                    withdraw_wens,
                    to_keyed,
                    &rent,
                    &signers,
                    &invoke_context,
                );
                assert_eq!(result, Err(SystemError::NonceBlockhashNotExpired.into()));
            })
        })
    }

    #[test]
    fn withdraw_inx_initialized_acc_insuff_funds_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let invoke_context = create_invoke_context_with_blockhash(95);
            let authorized = *nonce_keyed.unsigned_key();
            nonce_keyed
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            with_test_keyed_account(42, false, |to_keyed| {
                let invoke_context = create_invoke_context_with_blockhash(63);
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let withdraw_wens = nonce_keyed.account.borrow().wens() + 1;
                let result = nonce_keyed.withdraw_nonce_account(
                    withdraw_wens,
                    to_keyed,
                    &rent,
                    &signers,
                    &invoke_context,
                );
                assert_eq!(result, Err(InstructionError::InsufficientFunds));
            })
        })
    }

    #[test]
    fn withdraw_inx_initialized_acc_insuff_rent_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let invoke_context = create_invoke_context_with_blockhash(95);
            let authorized = *nonce_keyed.unsigned_key();
            nonce_keyed
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            with_test_keyed_account(42, false, |to_keyed| {
                let invoke_context = create_invoke_context_with_blockhash(63);
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let withdraw_wens = nonce_keyed.account.borrow().wens() - min_wens + 1;
                let result = nonce_keyed.withdraw_nonce_account(
                    withdraw_wens,
                    to_keyed,
                    &rent,
                    &signers,
                    &invoke_context,
                );
                assert_eq!(result, Err(InstructionError::InsufficientFunds));
            })
        })
    }

    #[test]
    fn withdraw_inx_overflow() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_keyed| {
            let invoke_context = create_invoke_context_with_blockhash(95);
            let authorized = *nonce_keyed.unsigned_key();
            nonce_keyed
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            with_test_keyed_account(55, false, |to_keyed| {
                let invoke_context = create_invoke_context_with_blockhash(63);
                let mut signers = HashSet::new();
                signers.insert(*nonce_keyed.signer_key().unwrap());
                let withdraw_wens = u64::MAX - 54;
                let result = nonce_keyed.withdraw_nonce_account(
                    withdraw_wens,
                    to_keyed,
                    &rent,
                    &signers,
                    &invoke_context,
                );
                assert_eq!(result, Err(InstructionError::InsufficientFunds));
            })
        })
    }

    #[test]
    fn initialize_inx_ok() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |keyed_account| {
            let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
            assert_eq!(versions.state(), &State::Uninitialized);
            let mut signers = HashSet::new();
            signers.insert(*keyed_account.signer_key().unwrap());
            let invoke_context = create_invoke_context_with_blockhash(0);
            let authority = *keyed_account.unsigned_key();
            let result = keyed_account.initialize_nonce_account(&authority, &rent, &invoke_context);
            let data = nonce::state::Data::new(
                authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            assert_eq!(result, Ok(()));
            let versions = AccountUtilsState::<Versions>::state(keyed_account).unwrap();
            assert_eq!(versions.state(), &State::Initialized(data));
        })
    }

    #[test]
    fn initialize_inx_initialized_account_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |keyed_account| {
            let invoke_context = create_invoke_context_with_blockhash(31);
            let authorized = *keyed_account.unsigned_key();
            keyed_account
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            let invoke_context = create_invoke_context_with_blockhash(0);
            let result =
                keyed_account.initialize_nonce_account(&authorized, &rent, &invoke_context);
            assert_eq!(result, Err(InstructionError::InvalidAccountData));
        })
    }

    #[test]
    fn initialize_inx_uninitialized_acc_insuff_funds_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens - 42, true, |keyed_account| {
            let invoke_context = create_invoke_context_with_blockhash(63);
            let authorized = *keyed_account.unsigned_key();
            let result =
                keyed_account.initialize_nonce_account(&authorized, &rent, &invoke_context);
            assert_eq!(result, Err(InstructionError::InsufficientFunds));
        })
    }

    #[test]
    fn authorize_inx_ok() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_account| {
            let mut signers = HashSet::new();
            signers.insert(*nonce_account.signer_key().unwrap());
            let invoke_context = create_invoke_context_with_blockhash(31);
            let authorized = *nonce_account.unsigned_key();
            nonce_account
                .initialize_nonce_account(&authorized, &rent, &invoke_context)
                .unwrap();
            let authority = Pubkey::default();
            let data = nonce::state::Data::new(
                authority,
                get_durable_nonce(&invoke_context).0,
                invoke_context.wens_per_signature,
            );
            let result = nonce_account.authorize_nonce_account(
                &Pubkey::default(),
                &signers,
                &invoke_context,
            );
            assert_eq!(result, Ok(()));
            let versions = AccountUtilsState::<Versions>::state(nonce_account).unwrap();
            assert_eq!(versions.state(), &State::Initialized(data));
        })
    }

    #[test]
    fn authorize_inx_uninitialized_state_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_account| {
            let mut signers = HashSet::new();
            signers.insert(*nonce_account.signer_key().unwrap());
            let result = nonce_account.authorize_nonce_account(
                &Pubkey::default(),
                &signers,
                &InvokeContext::new_mock(&[], &[]),
            );
            assert_eq!(result, Err(InstructionError::InvalidAccountData));
        })
    }

    #[test]
    fn authorize_inx_bad_authority_fail() {
        let rent = Rent {
            wens_per_byte_year: 42,
            ..Rent::default()
        };
        let min_wens = rent.minimum_balance(State::size());
        with_test_keyed_account(min_wens + 42, true, |nonce_account| {
            let mut signers = HashSet::new();
            signers.insert(*nonce_account.signer_key().unwrap());
            let invoke_context = create_invoke_context_with_blockhash(31);
            let authorized = &Pubkey::default().clone();
            nonce_account
                .initialize_nonce_account(authorized, &rent, &invoke_context)
                .unwrap();
            let result = nonce_account.authorize_nonce_account(
                &Pubkey::default(),
                &signers,
                &invoke_context,
            );
            assert_eq!(result, Err(InstructionError::MissingRequiredSignature));
        })
    }

    #[test]
    fn verify_nonce_ok() {
        with_test_keyed_account(42, true, |nonce_account| {
            let mut signers = HashSet::new();
            signers.insert(nonce_account.signer_key().unwrap());
            let versions: Versions = nonce_account.state().unwrap();
            // New is in Uninitialzed state
            assert_eq!(versions.state(), &State::Uninitialized);
            let invoke_context = create_invoke_context_with_blockhash(0);
            let authorized = nonce_account.unsigned_key();
            nonce_account
                .initialize_nonce_account(authorized, &Rent::free(), &invoke_context)
                .unwrap();
            assert_matches!(
                verify_nonce_account(
                    &nonce_account.account.borrow(),
                    get_durable_nonce(&invoke_context).0.as_hash(),
                    true, // separate_domains
                ),
                Some(_)
            );
        });
    }

    #[test]
    fn verify_nonce_bad_acc_state_fail() {
        with_test_keyed_account(42, true, |nonce_account| {
            assert_eq!(
                verify_nonce_account(
                    &nonce_account.account.borrow(),
                    &Hash::default(),
                    true, // separate_domains
                ),
                None,
            );
        });
    }

    #[test]
    fn verify_nonce_bad_query_hash_fail() {
        with_test_keyed_account(42, true, |nonce_account| {
            let mut signers = HashSet::new();
            signers.insert(nonce_account.signer_key().unwrap());
            let versions: Versions = nonce_account.state().unwrap();
            // New is in Uninitialzed state
            assert_eq!(versions.state(), &State::Uninitialized);
            let invoke_context = create_invoke_context_with_blockhash(0);
            let authorized = nonce_account.unsigned_key();
            nonce_account
                .initialize_nonce_account(authorized, &Rent::free(), &invoke_context)
                .unwrap();
            let invoke_context = create_invoke_context_with_blockhash(1);
            assert_eq!(
                verify_nonce_account(
                    &nonce_account.account.borrow(),
                    get_durable_nonce(&invoke_context).0.as_hash(),
                    true, // separate_domains
                ),
                None
            );
        });
    }
}
