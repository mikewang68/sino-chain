use crate::native_token::sor_to_wens;

/// A fee and its associated compute unit limit
#[derive(Debug, Default, Clone)]
pub struct FeeBin {
    /// maximum compute units for which this fee will be charged
    pub limit: u64,
    /// fee in wens
    pub fee: u64,
}

/// Information used to calculate fees
#[derive(Debug, Clone)]
pub struct FeeStructure {
    /// wens per signature
    pub wens_per_signature: u64,
    /// wens_per_write_lock
    pub wens_per_write_lock: u64,
    /// Compute unit fee bins
    pub compute_fee_bins: Vec<FeeBin>,
}

impl FeeStructure {
    pub fn new(
        sor_per_signature: f64,
        sor_per_write_lock: f64,
        compute_fee_bins: Vec<(u64, f64)>,
    ) -> Self {
        let compute_fee_bins = compute_fee_bins
            .iter()
            .map(|(limit, sor)| FeeBin {
                limit: *limit,
                fee: sor_to_wens(*sor),
            })
            .collect::<Vec<_>>();
        FeeStructure {
            wens_per_signature: sor_to_wens(sor_per_signature),
            wens_per_write_lock: sor_to_wens(sor_per_write_lock),
            compute_fee_bins,
        }
    }

    pub fn get_max_fee(&self, num_signatures: u64, num_write_locks: u64) -> u64 {
        num_signatures
            .saturating_mul(self.wens_per_signature)
            .saturating_add(num_write_locks.saturating_mul(self.wens_per_write_lock))
            .saturating_add(
                self.compute_fee_bins
                    .last()
                    .map(|bin| bin.fee)
                    .unwrap_or_default(),
            )
    }
}

impl Default for FeeStructure {
    fn default() -> Self {
        Self::new(0.000005, 0.0, vec![(1_400_000, 0.0)])
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl ::frozen_abi::abi_example::AbiExample for FeeStructure {
    fn example() -> Self {
        FeeStructure::default()
    }
}
