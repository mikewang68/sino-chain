#[cfg(RUSTC_WITH_SPECIALIZATION)]
use frozen_abi::abi_example::AbiExample;
#[cfg(debug_assertions)]
#[allow(deprecated)]

use {
    // crate::system_instruction_processor,
    program_runtime::{
        invoke_context::{ProcessInstructionWithContext},
    },
    sdk::{
        pubkey::Pubkey
    },
    std::fmt,
};

#[derive(Clone)]
pub struct Builtin {
    pub name: String,
    pub id: Pubkey,
    pub process_instruction_with_context: ProcessInstructionWithContext,
}

impl fmt::Debug for Builtin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Builtin [name={}, id={}]", self.name, self.id)
    }
}

#[cfg(RUSTC_WITH_SPECIALIZATION)]
impl AbiExample for Builtin {
    fn example() -> Self {
        Self {
            name: String::default(),
            id: Pubkey::default(),
            process_instruction_with_context: |_, _, _| Ok(()),
        }
    }
}

/// State transition enum used for adding and removing builtin programs through
/// feature activations.
#[derive(Debug, Clone, AbiExample)]
enum InnerBuiltinFeatureTransition {
    /// Add a builtin program if a feature is activated.
    Add {
        builtin: Builtin,
        feature_id: Pubkey,
    },
    /// Remove a builtin program if a feature is activated or
    /// retain a previously added builtin.
    RemoveOrRetain {
        previously_added_builtin: Builtin,
        addition_feature_id: Pubkey,
        removal_feature_id: Pubkey,
    },
}

#[derive(AbiExample, Clone, Debug)]
pub struct BuiltinFeatureTransition(InnerBuiltinFeatureTransition);

#[derive(Clone, Debug)]
pub struct Builtins {
    /// Builtin programs that are always available
    pub genesis_builtins: Vec<Builtin>,

    /// Dynamic feature transitions for builtin programs
    pub feature_transitions: Vec<BuiltinFeatureTransition>,
}