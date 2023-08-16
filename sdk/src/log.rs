#![cfg(feature = "program")]

pub use sino_program::log::*;

#[macro_export]
#[deprecated(
    since = "1.4.3",
    note = "Please use `sino_program::log::info` instead"
)]
macro_rules! info {
    ($msg:expr) => {
        $crate::log::sor_log($msg)
    };
}
