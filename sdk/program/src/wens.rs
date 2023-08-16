use {crate::instruction::InstructionError, thiserror::Error};

#[derive(Debug, Error)]
pub enum WensError {
    /// arithmetic underflowed
    #[error("Arithmetic underflowed")]
    ArithmeticUnderflow,

    /// arithmetic overflowed
    #[error("Arithmetic overflowed")]
    ArithmeticOverflow,
}

impl From<WensError> for InstructionError {
    fn from(error: WensError) -> Self {
        match error {
            WensError::ArithmeticOverflow => InstructionError::ArithmeticOverflow,
            WensError::ArithmeticUnderflow => InstructionError::ArithmeticOverflow,
        }
    }
}
