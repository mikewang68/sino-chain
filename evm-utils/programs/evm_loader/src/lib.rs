extern crate core;

mod account_structure;
pub mod tx_chunks;

pub mod error;
pub mod instructions;
pub mod precompiles;
pub mod processor;
pub mod extension;

pub static ID: sdk::pubkey::Pubkey = sdk::evm_loader::ID;

pub use account_structure::AccountStructure;
pub use processor::EvmProcessor;

/// Public API for intermediate eth <-> solana transfers
pub mod scope {
    pub mod evm {
        pub use evm_state::transactions::*;
        pub use evm_state::*;
        pub use primitive_types::H160 as Address;

        pub const WENS_TO_GWEI_PRICE: u64 = 1_000_000_000; // wens is 1/10^9 of SOLs while GWEI is 1/10^18

        // Convert lamports to gwei
        pub fn lamports_to_gwei(lamports: u64) -> U256 {
            U256::from(lamports) * U256::from(WENS_TO_GWEI_PRICE)
        }

        // Convert gweis back to lamports, return change as second element.
        pub fn gweis_to_lamports(gweis: U256) -> (u64, U256) {
            let lamports = gweis / U256::from(WENS_TO_GWEI_PRICE);
            let gweis = gweis % U256::from(WENS_TO_GWEI_PRICE);
            (lamports.as_u64(), gweis)
        }
    }
    pub mod solana {
        pub use sdk::{
            evm_state, instruction::Instruction, pubkey::Pubkey as Address,
            transaction::Transaction,
        };
    }
}
use instructions::{
    v0, EvmBigTransaction, EvmInstruction, ExecuteTransaction, FeePayerType,
    EVM_INSTRUCTION_BORSH_PREFIX,
};
use scope::*;
use sdk::instruction::{AccountMeta, Instruction};

/// Create an evm instruction and add EVM_INSTRUCTION_BORSH_PREFIX prefix
/// at the beginning of instruction data to mark Borsh encoding
pub fn create_evm_instruction_with_borsh(
    program_id: sdk::pubkey::Pubkey,
    data: &EvmInstruction,
    accounts: Vec<AccountMeta>,
) -> solana::Instruction {
    let mut res = Instruction::new_with_borsh(program_id, data, accounts);
    res.data.insert(0, EVM_INSTRUCTION_BORSH_PREFIX);
    res
}

/// Create an old version of evm instruction
pub fn create_evm_instruction_with_bincode(
    program_id: sdk::pubkey::Pubkey,
    data: &v0::EvmInstruction,
    accounts: Vec<AccountMeta>,
) -> solana::Instruction {
    Instruction::new_with_bincode(program_id, data, accounts)
}

pub fn send_raw_tx(
    signer: solana::Address,
    evm_tx: evm::Transaction,
    gas_collector: Option<solana::Address>,
    fee_type: FeePayerType,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(signer, true),
    ];
    if let Some(gas_collector) = gas_collector {
        account_metas.push(AccountMeta::new(gas_collector, false))
    }

    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::ExecuteTransaction {
            tx: ExecuteTransaction::Signed { tx: Some(evm_tx) },
            fee_type,
        },
        account_metas,
    )
}

pub fn authorized_tx(
    sender: solana::Address,
    unsigned_tx: evm::UnsignedTransaction,
    fee_type: FeePayerType,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(sender, true),
    ];

    let from = evm_address_for_program(sender);
    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::ExecuteTransaction {
            tx: ExecuteTransaction::ProgramAuthorized {
                tx: Some(unsigned_tx),
                from,
            },
            fee_type,
        },
        account_metas,
    )
}

pub(crate) fn transfer_native_to_evm(
    owner: solana::Address,
    lamports: u64,
    evm_address: evm::Address,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(owner, true),
    ];

    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::SwapNativeToEther {
            lamports,
            evm_address,
        },
        account_metas,
    )
}

pub fn free_ownership(owner: solana::Address) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(owner, true),
    ];

    create_evm_instruction_with_borsh(crate::ID, &EvmInstruction::FreeOwnership {}, account_metas)
}

pub fn big_tx_allocate(storage: solana::Address, size: usize) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    let big_tx = EvmBigTransaction::EvmTransactionAllocate { size: size as u64 };

    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}

pub fn big_tx_write(storage: solana::Address, offset: u64, chunk: Vec<u8>) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    let big_tx = EvmBigTransaction::EvmTransactionWrite {
        offset,
        data: chunk,
    };

    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}

pub fn big_tx_execute(
    storage: solana::Address,
    gas_collector: Option<&solana::Address>,
    fee_type: FeePayerType,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    if let Some(gas_collector) = gas_collector {
        account_metas.push(AccountMeta::new(*gas_collector, false))
    }

    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::ExecuteTransaction {
            tx: ExecuteTransaction::Signed { tx: None },
            fee_type,
        },
        account_metas,
    )
}
pub fn big_tx_execute_authorized(
    storage: solana::Address,
    from: evm::Address,
    gas_collector: solana::Address,
    fee_type: FeePayerType,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    if gas_collector != storage {
        account_metas.push(AccountMeta::new_readonly(gas_collector, true))
    }

    create_evm_instruction_with_borsh(
        crate::ID,
        &EvmInstruction::ExecuteTransaction {
            tx: ExecuteTransaction::ProgramAuthorized { tx: None, from },
            fee_type,
        },
        account_metas,
    )
}

pub fn transfer_native_to_evm_ixs(
    owner: solana::Address,
    lamports: u64,
    ether_address: evm::Address,
) -> Vec<solana::Instruction> {
    vec![
        sdk::system_instruction::assign(&owner, &crate::ID),
        transfer_native_to_evm(owner, lamports, ether_address),
        free_ownership(owner),
    ]
}

/// Create an account that represent evm locked lamports count.
pub fn create_state_account(lamports: u64) -> sdk::account::AccountSharedData {
    sdk::account::Account {
        lamports: lamports + 1,
        owner: crate::ID,
        data: b"Evm state".to_vec(),
        executable: false,
        rent_epoch: 0,
    }
    .into()
}

///
/// Calculate evm::Address for solana::Pubkey, that can be used to call transaction from solana::bpf scope, into evm scope.
/// Native chain address is hashed and prefixed with [0xac, 0xc0] bytes.
///
pub fn evm_address_for_program(program_account: solana::Address) -> evm::Address {
    use primitive_types::{H160, H256};
    use sha3::{Digest, Keccak256};

    const ADDR_PREFIX: &[u8] = &[0xAC, 0xC0]; // ACC prefix for each account

    let addr_hash = Keccak256::digest(&program_account.to_bytes());
    let hash_bytes = H256::from_slice(addr_hash.as_slice());
    let mut short_hash = H160::from(hash_bytes);
    short_hash.as_bytes_mut()[0..2].copy_from_slice(ADDR_PREFIX);

    short_hash
}

pub fn evm_transfer(
    from: evm::SecretKey,
    to: evm::Address,
    nonce: evm::U256,
    value: evm::U256,
    chain_id: Option<u64>,
) -> evm::Transaction {
    let tx = evm::UnsignedTransaction {
        nonce,
        gas_price: 1.into(),
        gas_limit: 21000.into(),
        action: evm::TransactionAction::Call(to),
        value,
        input: vec![],
    };
    tx.sign(&from, chain_id)
}

// old instructions for emv bridge

pub fn send_raw_tx_old(
    signer: solana::Address,
    evm_tx: evm::Transaction,
    gas_collector: Option<solana::Address>,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(signer, true),
    ];
    if let Some(gas_collector) = gas_collector {
        account_metas.push(AccountMeta::new(gas_collector, false))
    }

    create_evm_instruction_with_bincode(
        crate::ID,
        &v0::EvmInstruction::EvmTransaction { evm_tx },
        account_metas,
    )
}

pub fn big_tx_allocate_old(storage: solana::Address, size: usize) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    let big_tx = v0::EvmBigTransaction::EvmTransactionAllocate { size: size as u64 };

    create_evm_instruction_with_bincode(
        crate::ID,
        &v0::EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}

pub fn big_tx_write_old(
    storage: solana::Address,
    offset: u64,
    chunk: Vec<u8>,
) -> solana::Instruction {
    let account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    let big_tx = v0::EvmBigTransaction::EvmTransactionWrite {
        offset,
        data: chunk,
    };

    create_evm_instruction_with_bincode(
        crate::ID,
        &v0::EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}

pub fn big_tx_execute_old(
    storage: solana::Address,
    gas_collector: Option<&solana::Address>,
) -> solana::Instruction {
    let mut account_metas = vec![
        AccountMeta::new(solana::evm_state::ID, false),
        AccountMeta::new(storage, true),
    ];

    if let Some(gas_collector) = gas_collector {
        account_metas.push(AccountMeta::new(*gas_collector, false))
    }

    let big_tx = v0::EvmBigTransaction::EvmTransactionExecute {};

    create_evm_instruction_with_bincode(
        crate::ID,
        &v0::EvmInstruction::EvmBigTransaction(big_tx),
        account_metas,
    )
}
