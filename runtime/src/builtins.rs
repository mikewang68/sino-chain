#[cfg(RUSTC_WITH_SPECIALIZATION)]
use frozen_abi::abi_example::AbiExample;
#[cfg(debug_assertions)]
#[allow(deprecated)]
use {
    // crate::system_instruction_processor,
    program_runtime::{
        invoke_context::{InvokeContext, ProcessInstructionWithContext},
        stable_log,
    },
    sdk::{
        feature_set, instruction::InstructionError, pubkey::Pubkey, stake, /*system_program,*/
    },
    std::fmt,
};

fn process_instruction_with_program_logging(
    process_instruction: ProcessInstructionWithContext,
    first_instruction_account: usize,
    instruction_data: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let logger = invoke_context.get_log_collector();
    let program_id = invoke_context.get_caller()?;
    stable_log::program_invoke(&logger, program_id, invoke_context.get_stack_height());

    let result = process_instruction(first_instruction_account, instruction_data, invoke_context);

    let program_id = invoke_context.get_caller()?;
    match &result {
        Ok(()) => stable_log::program_success(&logger, program_id),
        Err(err) => stable_log::program_failure(&logger, program_id, err),
    }
    result
}

macro_rules! with_program_logging {
    ($process_instruction:expr) => {
        |first_instruction_account: usize,
         instruction_data: &[u8],
         invoke_context: &mut InvokeContext| {
            process_instruction_with_program_logging(
                $process_instruction,
                first_instruction_account,
                instruction_data,
                invoke_context,
            )
        }
    };
}

#[derive(Clone)]
pub struct Builtin {
    pub name: String,
    pub id: Pubkey,
    pub process_instruction_with_context: ProcessInstructionWithContext,
}

impl Builtin {
    pub fn new(
        name: &str,
        id: Pubkey,
        process_instruction_with_context: ProcessInstructionWithContext,
    ) -> Self {
        Self {
            name: name.to_string(),
            id,
            process_instruction_with_context,
        }
    }
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

/// Builtin programs that are always available
fn genesis_builtins() -> Vec<Builtin> {
    vec![
        // Builtin::new(
        //     "system_program",
        //     system_program::id(),
        //     with_program_logging!(system_instruction_processor::process_instruction),
        // ),
        Builtin::new(
            "vote_program",
            vote_program::id(),
            with_program_logging!(vote_program::vote_instruction::process_instruction),
        ),
        Builtin::new(
            "stake_program",
            stake::program::id(),
            with_program_logging!(stake_program::stake_instruction::process_instruction),
        ),
        // Builtin::new(
        //     "config_program",
        //     config_program::id(),
        //     with_program_logging!(config_program::config_processor::process_instruction),
        // ),
    ]
}

/// place holder for precompile programs, remove when the precompile program is deactivated via feature activation
fn dummy_process_instruction(
    _first_instruction_account: usize,
    _data: &[u8],
    _invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    Ok(())
}

/// Dynamic feature transitions for builtin programs
fn builtin_feature_transitions() -> Vec<BuiltinFeatureTransition> {
    vec![
        // BuiltinFeatureTransition(InnerBuiltinFeatureTransition::Add {
        //     builtin: Builtin::new(
        //         "compute_budget_program",
        //         sdk::compute_budget::id(),
        //         compute_budget_program::process_instruction,
        //     ),
        //     feature_id: feature_set::add_compute_budget_program::id(),
        // }),
        BuiltinFeatureTransition(InnerBuiltinFeatureTransition::RemoveOrRetain {
            previously_added_builtin: Builtin::new(
                "secp256k1_program",
                sdk::secp256k1_program::id(),
                dummy_process_instruction,
            ),
            addition_feature_id: feature_set::secp256k1_program_enabled::id(),
            removal_feature_id: feature_set::prevent_calling_precompiles_as_programs::id(),
        }),
        BuiltinFeatureTransition(InnerBuiltinFeatureTransition::RemoveOrRetain {
            previously_added_builtin: Builtin::new(
                "ed25519_program",
                sdk::ed25519_program::id(),
                dummy_process_instruction,
            ),
            addition_feature_id: feature_set::ed25519_program_enabled::id(),
            removal_feature_id: feature_set::prevent_calling_precompiles_as_programs::id(),
        }),
        // BuiltinFeatureTransition(InnerBuiltinFeatureTransition::Add {
        //     builtin: Builtin::new(
        //         "address_lookup_table_program",
        //         address_lookup_table_program::id(),
        //         address_lookup_table_program::processor::process_instruction,
        //     ),
        //     feature_id: feature_set::versioned_tx_message_enabled::id(),
        // }),
    ]
}

pub(crate) fn get() -> Builtins {
    Builtins {
        genesis_builtins: genesis_builtins(),
        feature_transitions: builtin_feature_transitions(),
    }
}
