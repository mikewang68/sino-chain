sdk::declare_builtin!(
    sdk::bpf_loader_upgradeable::ID,
    bpf_loader_upgradeable_program_with_jit,
    bpf_loader_program::process_instruction_jit,
    upgradeable_with_jit::id
);
