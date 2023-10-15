// Copyright 2020 Sino Maintainers <maintainers@sino.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#![feature(test)]

extern crate rbpf;
extern crate test;

use rbpf::{
    elf::Executable,
    user_error::UserError,
    vm::{Config, EbpfVm, SyscallRegistry, TestInstructionMeter},
};
use std::{fs::File, io::Read};
use test::Bencher;

#[bench]
fn bench_init_interpreter_execution(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let executable = Executable::<UserError, TestInstructionMeter>::from_elf(
        &elf,
        None,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    let mut vm =
        EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], &mut []).unwrap();
    bencher.iter(|| {
        vm.execute_program_interpreted(&mut TestInstructionMeter { remaining: 29 })
            .unwrap()
    });
}

#[cfg(not(windows))]
#[bench]
fn bench_init_jit_execution(bencher: &mut Bencher) {
    let mut file = File::open("tests/elfs/pass_stack_reference.so").unwrap();
    let mut elf = Vec::new();
    file.read_to_end(&mut elf).unwrap();
    let mut executable = Executable::<UserError, TestInstructionMeter>::from_elf(
        &elf,
        None,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable).unwrap();
    let mut vm =
        EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], &mut []).unwrap();
    bencher.iter(|| {
        vm.execute_program_jit(&mut TestInstructionMeter { remaining: 29 })
            .unwrap()
    });
}

#[cfg(not(windows))]
fn bench_jit_vs_interpreter(
    bencher: &mut Bencher,
    assembly: &str,
    instruction_meter: u64,
    mem: &mut [u8],
) {
    let mut executable = rbpf::assembler::assemble::<UserError, TestInstructionMeter>(
        assembly,
        None,
        Config::default(),
        SyscallRegistry::default(),
    )
    .unwrap();
    Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable).unwrap();
    let mut vm = EbpfVm::new(&executable, &mut [], mem).unwrap();
    let interpreter_summary = bencher
        .bench(|bencher| {
            bencher.iter(|| {
                let result = vm.execute_program_interpreted(&mut TestInstructionMeter {
                    remaining: instruction_meter,
                });
                assert!(result.is_ok());
                assert_eq!(vm.get_total_instruction_count(), instruction_meter);
            });
        })
        .unwrap();
    let jit_summary = bencher
        .bench(|bencher| {
            bencher.iter(|| {
                let result = vm.execute_program_jit(&mut TestInstructionMeter {
                    remaining: instruction_meter,
                });
                assert!(result.is_ok());
                assert_eq!(vm.get_total_instruction_count(), instruction_meter);
            });
        })
        .unwrap();
    println!(
        "jit_vs_interpreter_ratio={}",
        interpreter_summary.mean / jit_summary.mean
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_address_translation(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
    mov r1, r2
    and r1, 1023
    ldindb r1, 0
    add r2, 1
    jlt r2, 0x10000, -5
    exit",
        327681,
        &mut [0; 1024],
    );
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_vs_interpreter_empty_for_loop(bencher: &mut Bencher) {
    bench_jit_vs_interpreter(
        bencher,
        "
    mov r1, r2
    and r1, 1023
    add r2, 1
    jlt r2, 0x10000, -4
    exit",
        262145,
        &mut [0; 0],
    );
}
