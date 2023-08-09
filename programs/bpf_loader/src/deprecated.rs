sdk::declare_builtin!(
    sdk::bpf_loader_deprecated::ID,
    bpf_loader_deprecated_program,
    bpf_loader_program::process_instruction,
    deprecated::id
);
