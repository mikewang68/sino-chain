sdk::declare_builtin!(
    sdk::bpf_loader::ID,
    bpf_loader_program_with_jit,
    bpf_loader_program::process_instruction_jit
);
