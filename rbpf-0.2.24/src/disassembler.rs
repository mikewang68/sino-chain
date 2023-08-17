#![allow(clippy::integer_arithmetic)]
// Copyright 2017 6WIND S.A. <quentin.monnet@6wind.com>
//
// Licensed under the Apache License, Version 2.0 <http://www.apache.org/licenses/LICENSE-2.0> or
// the MIT license <http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Functions in this module are used to handle eBPF programs with a higher level representation,
//! for example to disassemble the code into a human-readable format.

use crate::ebpf;
use crate::error::UserDefinedError;
use crate::static_analysis::Analysis;
use crate::vm::InstructionMeter;

fn resolve_label<'a, E: UserDefinedError, I: InstructionMeter>(
    analysis: &'a Analysis<E, I>,
    pc: usize,
) -> &'a str {
    analysis
        .cfg_nodes
        .get(&pc)
        .map(|cfg_node| cfg_node.label.as_str())
        .unwrap_or("[invalid]")
}

#[inline]
fn alu_imm_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, {}", name, insn.dst, insn.imm)
}

#[inline]
fn alu_reg_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, r{}", name, insn.dst, insn.src)
}

#[inline]
fn byteswap_str(name: &str, insn: &ebpf::Insn) -> String {
    match insn.imm {
        16 | 32 | 64 => {}
        _ => println!(
            "[Disassembler] Warning: Invalid offset value for {} insn",
            name
        ),
    }
    format!("{}{} r{}", name, insn.imm, insn.dst)
}

#[inline]
fn signed_off_str(value: i16) -> String {
    if value < 0 {
        format!("-{:#x}", -value)
    } else {
        format!("+{:#x}", value)
    }
}

#[inline]
fn ld_st_imm_str(name: &str, insn: &ebpf::Insn) -> String {
    format!(
        "{} [r{}{}], {}",
        name,
        insn.dst,
        signed_off_str(insn.off),
        insn.imm
    )
}

#[inline]
fn ld_reg_str(name: &str, insn: &ebpf::Insn) -> String {
    format!(
        "{} r{}, [r{}{}]",
        name,
        insn.dst,
        insn.src,
        signed_off_str(insn.off)
    )
}

#[inline]
fn st_reg_str(name: &str, insn: &ebpf::Insn) -> String {
    format!(
        "{} [r{}{}], r{}",
        name,
        insn.dst,
        signed_off_str(insn.off),
        insn.src
    )
}

#[inline]
fn ldabs_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} {}", name, insn.imm)
}

#[inline]
fn ldind_str(name: &str, insn: &ebpf::Insn) -> String {
    format!("{} r{}, {}", name, insn.src, insn.imm)
}

#[inline]
fn jmp_imm_str<E: UserDefinedError, I: InstructionMeter>(
    name: &str,
    insn: &ebpf::Insn,
    analysis: &Analysis<E, I>,
) -> String {
    let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
    format!(
        "{} r{}, {}, {}",
        name,
        insn.dst,
        insn.imm,
        resolve_label(analysis, target_pc)
    )
}

#[inline]
fn jmp_reg_str<E: UserDefinedError, I: InstructionMeter>(
    name: &str,
    insn: &ebpf::Insn,
    analysis: &Analysis<E, I>,
) -> String {
    let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
    format!(
        "{} r{}, r{}, {}",
        name,
        insn.dst,
        insn.src,
        resolve_label(analysis, target_pc)
    )
}

/// Disassemble an eBPF instruction
#[rustfmt::skip]
pub fn disassemble_instruction<E: UserDefinedError, I: InstructionMeter>(insn: &ebpf::Insn, analysis: &Analysis<E, I>) -> String {
    let name;
    let desc;
    match insn.opc {
        // BPF_LD class
        ebpf::LD_ABS_B   => { name = "ldabsb";  desc = ldabs_str(name, insn); },
        ebpf::LD_ABS_H   => { name = "ldabsh";  desc = ldabs_str(name, insn); },
        ebpf::LD_ABS_W   => { name = "ldabsw";  desc = ldabs_str(name, insn); },
        ebpf::LD_ABS_DW  => { name = "ldabsdw"; desc = ldabs_str(name, insn); },
        ebpf::LD_IND_B   => { name = "ldindb";  desc = ldind_str(name, insn); },
        ebpf::LD_IND_H   => { name = "ldindh";  desc = ldind_str(name, insn); },
        ebpf::LD_IND_W   => { name = "ldindw";  desc = ldind_str(name, insn); },
        ebpf::LD_IND_DW  => { name = "ldinddw"; desc = ldind_str(name, insn); },

        ebpf::LD_DW_IMM  => { name = "lddw"; desc = format!("{} r{:}, {:#x}", name, insn.dst, insn.imm); },

        // BPF_LDX class
        ebpf::LD_B_REG   => { name = "ldxb";  desc = ld_reg_str(name, insn); },
        ebpf::LD_H_REG   => { name = "ldxh";  desc = ld_reg_str(name, insn); },
        ebpf::LD_W_REG   => { name = "ldxw";  desc = ld_reg_str(name, insn); },
        ebpf::LD_DW_REG  => { name = "ldxdw"; desc = ld_reg_str(name, insn); },

        // BPF_ST class
        ebpf::ST_B_IMM   => { name = "stb";  desc = ld_st_imm_str(name, insn); },
        ebpf::ST_H_IMM   => { name = "sth";  desc = ld_st_imm_str(name, insn); },
        ebpf::ST_W_IMM   => { name = "stw";  desc = ld_st_imm_str(name, insn); },
        ebpf::ST_DW_IMM  => { name = "stdw"; desc = ld_st_imm_str(name, insn); },

        // BPF_STX class
        ebpf::ST_B_REG   => { name = "stxb";      desc = st_reg_str(name, insn); },
        ebpf::ST_H_REG   => { name = "stxh";      desc = st_reg_str(name, insn); },
        ebpf::ST_W_REG   => { name = "stxw";      desc = st_reg_str(name, insn); },
        ebpf::ST_DW_REG  => { name = "stxdw";     desc = st_reg_str(name, insn); },
        ebpf::ST_W_XADD  => { name = "stxxaddw";  desc = st_reg_str(name, insn); },
        ebpf::ST_DW_XADD => { name = "stxxadddw"; desc = st_reg_str(name, insn); },

        // BPF_ALU class
        ebpf::ADD32_IMM  => { name = "add32";  desc = alu_imm_str(name, insn);  },
        ebpf::ADD32_REG  => { name = "add32";  desc = alu_reg_str(name, insn);  },
        ebpf::SUB32_IMM  => { name = "sub32";  desc = alu_imm_str(name, insn);  },
        ebpf::SUB32_REG  => { name = "sub32";  desc = alu_reg_str(name, insn);  },
        ebpf::MUL32_IMM  => { name = "mul32";  desc = alu_imm_str(name, insn);  },
        ebpf::MUL32_REG  => { name = "mul32";  desc = alu_reg_str(name, insn);  },
        ebpf::DIV32_IMM  => { name = "div32";  desc = alu_imm_str(name, insn);  },
        ebpf::DIV32_REG  => { name = "div32";  desc = alu_reg_str(name, insn);  },
        ebpf::OR32_IMM   => { name = "or32";   desc = alu_imm_str(name, insn);  },
        ebpf::OR32_REG   => { name = "or32";   desc = alu_reg_str(name, insn);  },
        ebpf::AND32_IMM  => { name = "and32";  desc = alu_imm_str(name, insn);  },
        ebpf::AND32_REG  => { name = "and32";  desc = alu_reg_str(name, insn);  },
        ebpf::LSH32_IMM  => { name = "lsh32";  desc = alu_imm_str(name, insn);  },
        ebpf::LSH32_REG  => { name = "lsh32";  desc = alu_reg_str(name, insn);  },
        ebpf::RSH32_IMM  => { name = "rsh32";  desc = alu_imm_str(name, insn);  },
        ebpf::RSH32_REG  => { name = "rsh32";  desc = alu_reg_str(name, insn);  },
        ebpf::NEG32      => { name = "neg32";  desc = format!("{} r{}", name, insn.dst); },
        ebpf::MOD32_IMM  => { name = "mod32";  desc = alu_imm_str(name, insn);  },
        ebpf::MOD32_REG  => { name = "mod32";  desc = alu_reg_str(name, insn);  },
        ebpf::XOR32_IMM  => { name = "xor32";  desc = alu_imm_str(name, insn);  },
        ebpf::XOR32_REG  => { name = "xor32";  desc = alu_reg_str(name, insn);  },
        ebpf::MOV32_IMM  => { name = "mov32";  desc = alu_imm_str(name, insn);  },
        ebpf::MOV32_REG  => { name = "mov32";  desc = alu_reg_str(name, insn);  },
        ebpf::ARSH32_IMM => { name = "arsh32"; desc = alu_imm_str(name, insn);  },
        ebpf::ARSH32_REG => { name = "arsh32"; desc = alu_reg_str(name, insn);  },
        ebpf::LE         => { name = "le";     desc = byteswap_str(name, insn); },
        ebpf::BE         => { name = "be";     desc = byteswap_str(name, insn); },

        // BPF_ALU64 class
        ebpf::ADD64_IMM  => { name = "add64";  desc = alu_imm_str(name, insn); },
        ebpf::ADD64_REG  => { name = "add64";  desc = alu_reg_str(name, insn); },
        ebpf::SUB64_IMM  => { name = "sub64";  desc = alu_imm_str(name, insn); },
        ebpf::SUB64_REG  => { name = "sub64";  desc = alu_reg_str(name, insn); },
        ebpf::MUL64_IMM  => { name = "mul64";  desc = alu_imm_str(name, insn); },
        ebpf::MUL64_REG  => { name = "mul64";  desc = alu_reg_str(name, insn); },
        ebpf::DIV64_IMM  => { name = "div64";  desc = alu_imm_str(name, insn); },
        ebpf::DIV64_REG  => { name = "div64";  desc = alu_reg_str(name, insn); },
        ebpf::OR64_IMM   => { name = "or64";   desc = alu_imm_str(name, insn); },
        ebpf::OR64_REG   => { name = "or64";   desc = alu_reg_str(name, insn); },
        ebpf::AND64_IMM  => { name = "and64";  desc = alu_imm_str(name, insn); },
        ebpf::AND64_REG  => { name = "and64";  desc = alu_reg_str(name, insn); },
        ebpf::LSH64_IMM  => { name = "lsh64";  desc = alu_imm_str(name, insn); },
        ebpf::LSH64_REG  => { name = "lsh64";  desc = alu_reg_str(name, insn); },
        ebpf::RSH64_IMM  => { name = "rsh64";  desc = alu_imm_str(name, insn); },
        ebpf::RSH64_REG  => { name = "rsh64";  desc = alu_reg_str(name, insn); },
        ebpf::NEG64      => { name = "neg64";  desc = format!("{} r{}", name, insn.dst); },
        ebpf::MOD64_IMM  => { name = "mod64";  desc = alu_imm_str(name, insn); },
        ebpf::MOD64_REG  => { name = "mod64";  desc = alu_reg_str(name, insn); },
        ebpf::XOR64_IMM  => { name = "xor64";  desc = alu_imm_str(name, insn); },
        ebpf::XOR64_REG  => { name = "xor64";  desc = alu_reg_str(name, insn); },
        ebpf::MOV64_IMM  => { name = "mov64";  desc = alu_imm_str(name, insn); },
        ebpf::MOV64_REG  => { name = "mov64";  desc = alu_reg_str(name, insn); },
        ebpf::ARSH64_IMM => { name = "arsh64"; desc = alu_imm_str(name, insn); },
        ebpf::ARSH64_REG => { name = "arsh64"; desc = alu_reg_str(name, insn); },

        // BPF_JMP class
        ebpf::JA         => {
            name = "ja";
            let target_pc = (insn.ptr as isize + insn.off as isize + 1) as usize;
            desc = format!("{} {}", name, resolve_label(analysis, target_pc));
        },
        ebpf::JEQ_IMM    => { name = "jeq";  desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JEQ_REG    => { name = "jeq";  desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JGT_IMM    => { name = "jgt";  desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JGT_REG    => { name = "jgt";  desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JGE_IMM    => { name = "jge";  desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JGE_REG    => { name = "jge";  desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JLT_IMM    => { name = "jlt";  desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JLT_REG    => { name = "jlt";  desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JLE_IMM    => { name = "jle";  desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JLE_REG    => { name = "jle";  desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JSET_IMM   => { name = "jset"; desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JSET_REG   => { name = "jset"; desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JNE_IMM    => { name = "jne";  desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JNE_REG    => { name = "jne";  desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JSGT_IMM   => { name = "jsgt"; desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JSGT_REG   => { name = "jsgt"; desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JSGE_IMM   => { name = "jsge"; desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JSGE_REG   => { name = "jsge"; desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JSLT_IMM   => { name = "jslt"; desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JSLT_REG   => { name = "jslt"; desc = jmp_reg_str(name, insn, analysis); },
        ebpf::JSLE_IMM   => { name = "jsle"; desc = jmp_imm_str(name, insn, analysis); },
        ebpf::JSLE_REG   => { name = "jsle"; desc = jmp_reg_str(name, insn, analysis); },
        ebpf::CALL_IMM   => {
            desc = if let Some(syscall_name) = analysis.executable.get_syscall_symbols().get(&(insn.imm as u32)) {
                name = "syscall";
                format!("{} {}", name, syscall_name)
            } else {
                name = "call";
                if let Some(target_pc) = analysis
                    .executable
                    .lookup_bpf_function(insn.imm as u32) {
                    format!("{} {}", name, resolve_label(analysis, target_pc))
                } else {
                    format!("{} [invalid]", name)
                }
            };
        },
        ebpf::CALL_REG   => { name = "callx"; desc = format!("{} r{}", name, insn.imm); },
        ebpf::EXIT       => { name = "exit"; desc = name.to_string(); },

        _                => { name = "unknown"; desc = format!("{} opcode={:#x}", name, insn.opc); },
    };
    desc
}
