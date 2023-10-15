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
fn bench_init_vm(bencher: &mut Bencher) {
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
    bencher.iter(|| {
        EbpfVm::<UserError, TestInstructionMeter>::new(&executable, &mut [], &mut []).unwrap()
    });
}

#[cfg(not(windows))]
#[bench]
fn bench_jit_compile(bencher: &mut Bencher) {
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
    bencher.iter(|| {
        Executable::<UserError, TestInstructionMeter>::jit_compile(&mut executable).unwrap()
    });
}
