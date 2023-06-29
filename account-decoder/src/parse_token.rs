use {
    crate::{
        parse_account_data::{ParsableAccount, ParseAccountError},
        StringAmount, StringDecimals,
    },
    sdk::pubkey::Pubkey,
    spl_token::{
        solana_program::{
            program_option::COption, program_pack::Pack, pubkey::Pubkey as SplTokenPubkey,
        },
        state::{Account, AccountState, Mint, Multisig},
    },
    std::str::FromStr,
};

// A helper function to convert spl_token::id() as spl_sdk::pubkey::Pubkey to
// solana_sdk::pubkey::Pubkey
fn spl_token_id() -> Pubkey {
    Pubkey::new_from_array(spl_token::id().to_bytes())
}

// Returns all known SPL Token program ids
pub fn spl_token_ids() -> Vec<Pubkey> {
    vec![spl_token_id()]
}

// Check if the provided program id as a known SPL Token program id
pub fn is_known_spl_token_id(program_id: &Pubkey) -> bool {
    *program_id == spl_token_id()
}

// A helper function to convert spl_token::native_mint::id() as spl_sdk::pubkey::Pubkey to
// solana_sdk::pubkey::Pubkey
pub fn spl_token_native_mint() -> Pubkey {
    Pubkey::new_from_array(spl_token::native_mint::id().to_bytes())
}

// The program id of the `spl_token_native_mint` account
pub fn spl_token_native_mint_program_id() -> Pubkey {
    spl_token_id()
}

// A helper function to convert a solana_sdk::pubkey::Pubkey to spl_sdk::pubkey::Pubkey
pub fn spl_token_pubkey(pubkey: &Pubkey) -> SplTokenPubkey {
    SplTokenPubkey::new_from_array(pubkey.to_bytes())
}

// A helper function to convert a spl_sdk::pubkey::Pubkey to solana_sdk::pubkey::Pubkey
pub fn pubkey_from_spl_token(pubkey: &SplTokenPubkey) -> Pubkey {
    Pubkey::new_from_array(pubkey.to_bytes())
}

pub fn parse_token(
    data: &[u8],
    mint_decimals: Option<u8>,
) -> Result<TokenAccountType, ParseAccountError> {
    if data.len() == Account::get_packed_len() {
        let account = Account::unpack(data)
            .map_err(|_| ParseAccountError::AccountNotParsable(ParsableAccount::SplToken))?;
        let decimals = mint_decimals.ok_or_else(|| {
            ParseAccountError::AdditionalDataMissing(
                "no mint_decimals provided to parse spl-token account".to_string(),
            )
        })?;
        Ok(TokenAccountType::Account(UiTokenAccount {
            mint: account.mint.to_string(),
            owner: account.owner.to_string(),
            token_amount: token_amount_to_ui_amount(account.amount, decimals),
            delegate: match account.delegate {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
            state: account.state.into(),
            is_native: account.is_native(),
            rent_exempt_reserve: match account.is_native {
                COption::Some(reserve) => Some(token_amount_to_ui_amount(reserve, decimals)),
                COption::None => None,
            },
            delegated_amount: if account.delegate.is_none() {
                None
            } else {
                Some(token_amount_to_ui_amount(
                    account.delegated_amount,
                    decimals,
                ))
            },
            close_authority: match account.close_authority {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
        }))
    } else if data.len() == Mint::get_packed_len() {
        let mint = Mint::unpack(data)
            .map_err(|_| ParseAccountError::AccountNotParsable(ParsableAccount::SplToken))?;
        Ok(TokenAccountType::Mint(UiMint {
            mint_authority: match mint.mint_authority {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
            supply: mint.supply.to_string(),
            decimals: mint.decimals,
            is_initialized: mint.is_initialized,
            freeze_authority: match mint.freeze_authority {
                COption::Some(pubkey) => Some(pubkey.to_string()),
                COption::None => None,
            },
        }))
    } else if data.len() == Multisig::get_packed_len() {
        let multisig = Multisig::unpack(data)
            .map_err(|_| ParseAccountError::AccountNotParsable(ParsableAccount::SplToken))?;
        Ok(TokenAccountType::Multisig(UiMultisig {
            num_required_signers: multisig.m,
            num_valid_signers: multisig.n,
            is_initialized: multisig.is_initialized,
            signers: multisig
                .signers
                .iter()
                .filter_map(|pubkey| {
                    if pubkey != &SplTokenPubkey::default() {
                        Some(pubkey.to_string())
                    } else {
                        None
                    }
                })
                .collect(),
        }))
    } else {
        Err(ParseAccountError::AccountNotParsable(
            ParsableAccount::SplToken,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", tag = "type", content = "info")]
#[allow(clippy::large_enum_variant)]
pub enum TokenAccountType {
    Account(UiTokenAccount),
    Mint(UiMint),
    Multisig(UiMultisig),
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UiTokenAccount {
    pub mint: String,
    pub owner: String,
    pub token_amount: UiTokenAmount,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegate: Option<String>,
    pub state: UiAccountState,
    pub is_native: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rent_exempt_reserve: Option<UiTokenAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_amount: Option<UiTokenAmount>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub close_authority: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub enum UiAccountState {
    Uninitialized,
    Initialized,
    Frozen,
}

impl From<AccountState> for UiAccountState {
    fn from(state: AccountState) -> Self {
        match state {
            AccountState::Uninitialized => UiAccountState::Uninitialized,
            AccountState::Initialized => UiAccountState::Initialized,
            AccountState::Frozen => UiAccountState::Frozen,
        }
    }
}

pub fn real_number_string(amount: u64, decimals: u8) -> StringDecimals {
    let decimals = decimals as usize;
    if decimals > 0 {
        // Left-pad zeros to decimals + 1, so we at least have an integer zero
        let mut s = format!("{:01$}", amount, decimals + 1);
        // Add the decimal point (Sorry, "," locales!)
        s.insert(s.len() - decimals, '.');
        s
    } else {
        amount.to_string()
    }
}

pub fn real_number_string_trimmed(amount: u64, decimals: u8) -> StringDecimals {
    let mut s = real_number_string(amount, decimals);
    if decimals > 0 {
        let zeros_trimmed = s.trim_end_matches('0');
        s = zeros_trimmed.trim_end_matches('.').to_string();
    }
    s
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UiTokenAmount {
    pub ui_amount: Option<f64>,
    pub decimals: u8,
    pub amount: StringAmount,
    pub ui_amount_string: StringDecimals,
}

impl UiTokenAmount {
    pub fn real_number_string(&self) -> String {
        real_number_string(
            u64::from_str(&self.amount).unwrap_or_default(),
            self.decimals,
        )
    }

    pub fn real_number_string_trimmed(&self) -> String {
        if !self.ui_amount_string.is_empty() {
            self.ui_amount_string.clone()
        } else {
            real_number_string_trimmed(
                u64::from_str(&self.amount).unwrap_or_default(),
                self.decimals,
            )
        }
    }
}

pub fn token_amount_to_ui_amount(amount: u64, decimals: u8) -> UiTokenAmount {
    let amount_decimals = 10_usize
        .checked_pow(decimals as u32)
        .map(|dividend| amount as f64 / dividend as f64);
    UiTokenAmount {
        ui_amount: amount_decimals,
        decimals,
        amount: amount.to_string(),
        ui_amount_string: real_number_string_trimmed(amount, decimals),
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UiMint {
    pub mint_authority: Option<String>,
    pub supply: StringAmount,
    pub decimals: u8,
    pub is_initialized: bool,
    pub freeze_authority: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct UiMultisig {
    pub num_required_signers: u8,
    pub num_valid_signers: u8,
    pub is_initialized: bool,
    pub signers: Vec<String>,
}

pub fn get_token_account_mint(data: &[u8]) -> Option<Pubkey> {
    if data.len() == Account::get_packed_len() {
        Some(Pubkey::new(&data[0..32]))
    } else {
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_token() {
        let mint_pubkey = SplTokenPubkey::new(&[2; 32]);
        let owner_pubkey = SplTokenPubkey::new(&[3; 32]);
        let mut account_data = vec![0; Account::get_packed_len()];
        let mut account = Account::unpack_unchecked(&account_data).unwrap();
        account.mint = mint_pubkey;
        account.owner = owner_pubkey;
        account.amount = 42;
        account.state = AccountState::Initialized;
        account.is_native = COption::None;
        account.close_authority = COption::Some(owner_pubkey);
        Account::pack(account, &mut account_data).unwrap();

        assert!(parse_token(&account_data, None).is_err());
        assert_eq!(
            parse_token(&account_data, Some(2)).unwrap(),
            TokenAccountType::Account(UiTokenAccount {
                mint: mint_pubkey.to_string(),
                owner: owner_pubkey.to_string(),
                token_amount: UiTokenAmount {
                    ui_amount: Some(0.42),
                    decimals: 2,
                    amount: "42".to_string(),
                    ui_amount_string: "0.42".to_string()
                },
                delegate: None,
                state: UiAccountState::Initialized,
                is_native: false,
                rent_exempt_reserve: None,
                delegated_amount: None,
                close_authority: Some(owner_pubkey.to_string()),
            }),
        );

        let mut mint_data = vec![0; Mint::get_packed_len()];
        let mut mint = Mint::unpack_unchecked(&mint_data).unwrap();
        mint.mint_authority = COption::Some(owner_pubkey);
        mint.supply = 42;
        mint.decimals = 3;
        mint.is_initialized = true;
        mint.freeze_authority = COption::Some(owner_pubkey);
        Mint::pack(mint, &mut mint_data).unwrap();

        assert_eq!(
            parse_token(&mint_data, None).unwrap(),
            TokenAccountType::Mint(UiMint {
                mint_authority: Some(owner_pubkey.to_string()),
                supply: 42.to_string(),
                decimals: 3,
                is_initialized: true,
                freeze_authority: Some(owner_pubkey.to_string()),
            }),
        );

        let signer1 = SplTokenPubkey::new(&[1; 32]);
        let signer2 = SplTokenPubkey::new(&[2; 32]);
        let signer3 = SplTokenPubkey::new(&[3; 32]);
        let mut multisig_data = vec![0; Multisig::get_packed_len()];
        let mut signers = [SplTokenPubkey::default(); 11];
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;
        let mut multisig = Multisig::unpack_unchecked(&multisig_data).unwrap();
        multisig.m = 2;
        multisig.n = 3;
        multisig.is_initialized = true;
        multisig.signers = signers;
        Multisig::pack(multisig, &mut multisig_data).unwrap();

        assert_eq!(
            parse_token(&multisig_data, None).unwrap(),
            TokenAccountType::Multisig(UiMultisig {
                num_required_signers: 2,
                num_valid_signers: 3,
                is_initialized: true,
                signers: vec![
                    signer1.to_string(),
                    signer2.to_string(),
                    signer3.to_string()
                ],
            }),
        );

        let bad_data = vec![0; 4];
        assert!(parse_token(&bad_data, None).is_err());
    }

    #[test]
    fn test_get_token_account_mint() {
        let mint_pubkey = SplTokenPubkey::new(&[2; 32]);
        let mut account_data = vec![0; Account::get_packed_len()];
        let mut account = Account::unpack_unchecked(&account_data).unwrap();
        account.mint = mint_pubkey;
        Account::pack(account, &mut account_data).unwrap();

        let expected_mint_pubkey = Pubkey::new(&[2; 32]);
        assert_eq!(
            get_token_account_mint(&account_data),
            Some(expected_mint_pubkey)
        );
    }

    #[test]
    fn test_ui_token_amount_real_string() {
        assert_eq!(&real_number_string(1, 0), "1");
        assert_eq!(&real_number_string_trimmed(1, 0), "1");
        let token_amount = token_amount_to_ui_amount(1, 0);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(1, 0)
        );
        assert_eq!(token_amount.ui_amount, Some(1.0));
        assert_eq!(&real_number_string(10, 0), "10");
        assert_eq!(&real_number_string_trimmed(10, 0), "10");
        let token_amount = token_amount_to_ui_amount(10, 0);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(10, 0)
        );
        assert_eq!(token_amount.ui_amount, Some(10.0));
        assert_eq!(&real_number_string(1, 9), "0.000000001");
        assert_eq!(&real_number_string_trimmed(1, 9), "0.000000001");
        let token_amount = token_amount_to_ui_amount(1, 9);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(1, 9)
        );
        assert_eq!(token_amount.ui_amount, Some(0.000000001));
        assert_eq!(&real_number_string(1_000_000_000, 9), "1.000000000");
        assert_eq!(&real_number_string_trimmed(1_000_000_000, 9), "1");
        let token_amount = token_amount_to_ui_amount(1_000_000_000, 9);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(1_000_000_000, 9)
        );
        assert_eq!(token_amount.ui_amount, Some(1.0));
        assert_eq!(&real_number_string(1_234_567_890, 3), "1234567.890");
        assert_eq!(&real_number_string_trimmed(1_234_567_890, 3), "1234567.89");
        let token_amount = token_amount_to_ui_amount(1_234_567_890, 3);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(1_234_567_890, 3)
        );
        assert_eq!(token_amount.ui_amount, Some(1234567.89));
        assert_eq!(
            &real_number_string(1_234_567_890, 25),
            "0.0000000000000001234567890"
        );
        assert_eq!(
            &real_number_string_trimmed(1_234_567_890, 25),
            "0.000000000000000123456789"
        );
        let token_amount = token_amount_to_ui_amount(1_234_567_890, 20);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(1_234_567_890, 20)
        );
        assert_eq!(token_amount.ui_amount, None);
    }

    #[test]
    fn test_ui_token_amount_real_string_zero() {
        assert_eq!(&real_number_string(0, 0), "0");
        assert_eq!(&real_number_string_trimmed(0, 0), "0");
        let token_amount = token_amount_to_ui_amount(0, 0);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(0, 0)
        );
        assert_eq!(token_amount.ui_amount, Some(0.0));
        assert_eq!(&real_number_string(0, 9), "0.000000000");
        assert_eq!(&real_number_string_trimmed(0, 9), "0");
        let token_amount = token_amount_to_ui_amount(0, 9);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(0, 9)
        );
        assert_eq!(token_amount.ui_amount, Some(0.0));
        assert_eq!(&real_number_string(0, 25), "0.0000000000000000000000000");
        assert_eq!(&real_number_string_trimmed(0, 25), "0");
        let token_amount = token_amount_to_ui_amount(0, 20);
        assert_eq!(
            token_amount.ui_amount_string,
            real_number_string_trimmed(0, 20)
        );
        assert_eq!(token_amount.ui_amount, None);
    }
}
