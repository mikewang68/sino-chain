sdk::declare_builtin!(
    sdk::bpf_loader_upgradeable::ID,
    bpf_loader_upgradeable_program,
    bpf_loader_program::process_instruction,
    upgradeable::id
);
