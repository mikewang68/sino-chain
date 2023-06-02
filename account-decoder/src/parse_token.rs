use {
    crate::{
        StringAmount, 
        StringDecimals,
    },
    std::str::FromStr,
};


// -----------
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
// -----------
pub fn real_number_string_trimmed(amount: u64, decimals: u8) -> StringDecimals {
    let mut s = real_number_string(amount, decimals);
    if decimals > 0 {
        let zeros_trimmed = s.trim_end_matches('0');
        s = zeros_trimmed.trim_end_matches('.').to_string();
    }
    s
}
// -----------

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
