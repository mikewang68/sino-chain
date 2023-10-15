//! Sino builtin helper macros

#[rustversion::since(1.46.0)]
#[macro_export]
macro_rules! declare_builtin_name {
    ($name:ident, $id:path, $entrypoint:expr) => {
        #[macro_export]
        macro_rules! $name {
            () => {
                // Subtle:
                // The outer `declare_builtin_name!` macro may be expanded in another
                // crate, causing the macro `$name!` to be defined in that
                // crate. We want to emit a call to `$crate::id()`, and have
                // `$crate` be resolved in the crate where `$name!` gets defined,
                // *not* in this crate (where `declare_builtin_name! is defined).
                //
                // When a macro_rules! macro gets expanded, any $crate tokens
                // in its output will be 'marked' with the crate they were expanded
                // from. This includes nested macros like our macro `$name` - even
                // though it looks like a separate macro, Rust considers it to be
                // just another part of the output of `declare_program!`.
                //
                // We pass `$name` as the second argument to tell `respan!` to
                // apply use the `Span` of `$name` when resolving `$crate::id`.
                // This causes `$crate` to behave as though it was written
                // at the same location as the `$name` value passed
                // to `declare_builtin_name!` (e.g. the 'foo' in
                // `declare_builtin_name(foo)`
                //
                // See the `respan!` macro for more details.
                // This should use `crate::respan!` once
                // https://github.com/rust-lang/rust/pull/72121 is merged:
                // see https://github.com/sino-labs/sino/issues/10933.
                // For now, we need to use `::sdk`
                //
                // `respan!` respans the path `$crate::id`, which we then call (hence the extra
                // parens)
                (
                    stringify!($name).to_string(),
                    ::sdk::respan!($crate::$id, $name)(),
                    $entrypoint,
                )
            };
        }
    };
}

#[rustversion::not(since(1.46.0))]
#[macro_export]
macro_rules! declare_builtin_name {
    ($name:ident, $id:path, $entrypoint:expr) => {
        #[macro_export]
        macro_rules! $name {
            () => {
                (stringify!($name).to_string(), $crate::$id(), $entrypoint)
            };
        }
    };
}

/// Convenience macro to declare a builtin
///
/// bs58_string: bs58 string representation the program's id
/// name: Name of the program
/// entrypoint: Program's entrypoint, must be of `type Entrypoint`
/// id: Path to the program id access function, used if this macro is not
///     called in `src/lib`
///
/// # Examples
///
/// ```
/// use std::str::FromStr;
/// // wrapper is used so that the macro invocation occurs in the item position
/// // rather than in the statement position which isn't allowed.
/// mod item_wrapper {
/// use sdk::keyed_account::KeyedAccount;
/// use sdk::instruction::InstructionError;
/// use sdk::pubkey::Pubkey;
/// use sdk::declare_builtin;
///
/// fn my_process_instruction(
///     first_instruction_account: usize,
///     keyed_accounts: &[KeyedAccount],
///     instruction_data: &[u8],
/// ) -> Result<(), InstructionError> {
///   // Process an instruction
///   Ok(())
/// }
///
/// declare_builtin!(
///     "My11111111111111111111111111111111111111111",
///     sino_my_program,
///     my_process_instruction
/// );
///
/// # }
/// # use sdk::pubkey::Pubkey;
/// # use item_wrapper::id;
/// let my_id = Pubkey::from_str("My11111111111111111111111111111111111111111").unwrap();
/// assert_eq!(id(), my_id);
/// ```
/// ```
/// use std::str::FromStr;
/// # // wrapper is used so that the macro invocation occurs in the item position
/// # // rather than in the statement position which isn't allowed.
/// # mod item_wrapper {
/// use sdk::keyed_account::KeyedAccount;
/// use sdk::instruction::InstructionError;
/// use sdk::pubkey::Pubkey;
/// use sdk::declare_builtin;
///
/// fn my_process_instruction(
///     first_instruction_account: usize,
///     keyed_accounts: &[KeyedAccount],
///     instruction_data: &[u8],
/// ) -> Result<(), InstructionError> {
///   // Process an instruction
///   Ok(())
/// }
///
/// declare_builtin!(
///     sdk::system_program::ID,
///     sino_my_program,
///     my_process_instruction
/// );
/// }
///
/// # use item_wrapper::id;
/// assert_eq!(id(), sdk::system_program::ID);
/// ```
#[macro_export]
macro_rules! declare_builtin {
    ($bs58_string:expr, $name:ident, $entrypoint:expr) => {
        $crate::declare_builtin!($bs58_string, $name, $entrypoint, id);
    };
    ($bs58_string:expr, $name:ident, $entrypoint:expr, $id:path) => {
        $crate::declare_id!($bs58_string);
        $crate::declare_builtin_name!($name, $id, $entrypoint);
    };
}
