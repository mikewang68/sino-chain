#![allow(clippy::integer_arithmetic)]
/// There are 10^9 wens in one SOR
pub const WENS_PER_SOR: u64 = 1_000_000_000;

/// Approximately convert fractional native tokens (wens) into native tokens (SOR)
pub fn wens_to_sor(wens: u64) -> f64 {
    wens as f64 / WENS_PER_SOR as f64
}

/// Approximately convert native tokens (SOR) into fractional native tokens (wens)
pub fn sor_to_wens(sor: f64) -> u64 {
    (sor * WENS_PER_SOR as f64) as u64
}

use std::fmt::{Debug, Display, Formatter, Result};
pub struct Sor(pub u64);

impl Sor {
    fn write_in_sor(&self, f: &mut Formatter) -> Result {
        write!(
            f,
            "◎{}.{:09}",
            self.0 / WENS_PER_SOR,
            self.0 % WENS_PER_SOR
        )
    }
}

impl Display for Sor {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_in_sor(f)
    }
}

impl Debug for Sor {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.write_in_sor(f)
    }
}
