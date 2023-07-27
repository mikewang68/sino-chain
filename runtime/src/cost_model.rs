//! 'cost_model` provides service to estimate a transaction's cost
//! following proposed fee schedule #16984; Relevant cluster cost
//! measuring is described by #19627
//!
//! The main function is `calculate_cost` which returns &TransactionCost.
//!
use {
    crate::{block_cost_limits::*, execute_cost_table::ExecuteCostTable},
    log::*,
    sdk::{pubkey::Pubkey, transaction::SanitizedTransaction},
    std::collections::HashMap,
};

const MAX_WRITABLE_ACCOUNTS: usize = 256;

// costs are stored in number of 'compute unit's
#[derive(Debug)]
pub struct TransactionCost {
    pub writable_accounts: Vec<Pubkey>,
    pub signature_cost: u64,
    pub write_lock_cost: u64,
    pub data_bytes_cost: u64,
    pub builtins_execution_cost: u64,
    pub bpf_execution_cost: u64,
    pub is_simple_vote: bool,
}

impl Default for TransactionCost {
    fn default() -> Self {
        Self {
            writable_accounts: Vec::with_capacity(MAX_WRITABLE_ACCOUNTS),
            signature_cost: 0u64,
            write_lock_cost: 0u64,
            data_bytes_cost: 0u64,
            builtins_execution_cost: 0u64,
            bpf_execution_cost: 0u64,
            is_simple_vote: false,
        }
    }
}

impl TransactionCost {
    pub fn new_with_capacity(capacity: usize) -> Self {
        Self {
            writable_accounts: Vec::with_capacity(capacity),
            ..Self::default()
        }
    }

    pub fn reset(&mut self) {
        self.writable_accounts.clear();
        self.signature_cost = 0;
        self.write_lock_cost = 0;
        self.data_bytes_cost = 0;
        self.builtins_execution_cost = 0;
        self.bpf_execution_cost = 0;
        self.is_simple_vote = false;
    }

    pub fn sum(&self) -> u64 {
        self.signature_cost
            .saturating_add(self.write_lock_cost)
            .saturating_add(self.data_bytes_cost)
            .saturating_add(self.builtins_execution_cost)
            .saturating_add(self.bpf_execution_cost)
    }
}

#[derive(Debug, Default)]
pub struct CostModel {
    instruction_execution_cost_table: ExecuteCostTable,
}

impl CostModel {
    pub fn new() -> Self {
        Self {
            instruction_execution_cost_table: ExecuteCostTable::default(),
        }
    }

    pub fn initialize_cost_table(&mut self, cost_table: &[(Pubkey, u64)]) {
        cost_table
            .iter()
            .map(|(key, cost)| (key, cost))
            .for_each(|(program_id, cost)| {
                match self
                    .instruction_execution_cost_table
                    .upsert(program_id, *cost)
                {
                    Some(c) => {
                        debug!(
                            "initiating cost table, instruction {:?} has cost {}",
                            program_id, c
                        );
                    }
                    None => {
                        debug!(
                            "initiating cost table, failed for instruction {:?}",
                            program_id
                        );
                    }
                }
            });
        debug!(
            "restored cost model instruction cost table from blockstore, current values: {:?}",
            self.get_instruction_cost_table()
        );
    }

    pub fn calculate_cost(&self, transaction: &SanitizedTransaction) -> TransactionCost {
        let mut tx_cost = TransactionCost::new_with_capacity(MAX_WRITABLE_ACCOUNTS);

        tx_cost.signature_cost = self.get_signature_cost(transaction);
        self.get_write_lock_cost(&mut tx_cost, transaction);
        tx_cost.data_bytes_cost = self.get_data_bytes_cost(transaction);
        let (builtins_cost, bpf_cost) = self.get_transaction_cost(transaction);
        tx_cost.builtins_execution_cost = builtins_cost;
        tx_cost.bpf_execution_cost = bpf_cost;
        tx_cost.is_simple_vote = transaction.is_simple_vote_transaction();

        debug!("transaction {:?} has cost {:?}", transaction, tx_cost);
        tx_cost
    }

    pub fn upsert_instruction_cost(
        &mut self,
        program_key: &Pubkey,
        cost: u64,
    ) -> Result<u64, &'static str> {
        self.instruction_execution_cost_table
            .upsert(program_key, cost);
        match self.instruction_execution_cost_table.get_cost(program_key) {
            Some(cost) => Ok(*cost),
            None => Err("failed to upsert to ExecuteCostTable"),
        }
    }

    pub fn get_instruction_cost_table(&self) -> &HashMap<Pubkey, u64> {
        self.instruction_execution_cost_table.get_cost_table()
    }

    pub fn find_instruction_cost(&self, program_key: &Pubkey) -> u64 {
        match self.instruction_execution_cost_table.get_cost(program_key) {
            Some(cost) => *cost,
            None => {
                let default_value = self.instruction_execution_cost_table.get_mode();
                debug!(
                    "Program key {:?} does not have assigned cost, using mode {}",
                    program_key, default_value
                );
                default_value
            }
        }
    }

    pub fn get_program_keys(&self) -> Vec<&Pubkey> {
        self.instruction_execution_cost_table.get_program_keys()
    }

    fn get_signature_cost(&self, transaction: &SanitizedTransaction) -> u64 {
        transaction.signatures().len() as u64 * SIGNATURE_COST
    }

    fn get_write_lock_cost(
        &self,
        tx_cost: &mut TransactionCost,
        transaction: &SanitizedTransaction,
    ) {
        let message = transaction.message();
        message.account_keys_iter().enumerate().for_each(|(i, k)| {
            let is_writable = message.is_writable(i);

            if is_writable {
                tx_cost.writable_accounts.push(*k);
                tx_cost.write_lock_cost += WRITE_LOCK_UNITS;
            }
        });
    }

    fn get_data_bytes_cost(&self, transaction: &SanitizedTransaction) -> u64 {
        let mut data_bytes_cost: u64 = 0;
        transaction
            .message()
            .program_instructions_iter()
            .for_each(|(_, ix)| {
                data_bytes_cost += ix.data.len() as u64 / DATA_BYTES_UNITS;
            });
        data_bytes_cost
    }

    fn get_transaction_cost(&self, transaction: &SanitizedTransaction) -> (u64, u64) {
        let mut builtin_costs = 0u64;
        let mut bpf_costs = 0u64;

        for (program_id, instruction) in transaction.message().program_instructions_iter() {
            // to keep the same behavior, look for builtin first
            if let Some(builtin_cost) = BUILT_IN_INSTRUCTION_COSTS.get(program_id) {
                builtin_costs = builtin_costs.saturating_add(*builtin_cost);
            } else {
                let instruction_cost = self.find_instruction_cost(program_id);
                trace!(
                    "instruction {:?} has cost of {}",
                    instruction,
                    instruction_cost
                );
                bpf_costs = bpf_costs.saturating_add(instruction_cost);
            }
        }
        (builtin_costs, bpf_costs)
    }
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        crate::{
            bank::Bank,
            genesis_utils::{create_genesis_config, GenesisConfigInfo},
        },
        sdk::{
            bpf_loader,
            hash::Hash,
            instruction::CompiledInstruction,
            message::Message,
            signature::{Keypair, Signer},
            system_instruction::{self},
            system_program, system_transaction,
            transaction::Transaction,
        },
        std::{
            str::FromStr,
            sync::{Arc, RwLock},
            thread::{self, JoinHandle},
        },
    };

    fn test_setup() -> (Keypair, Hash) {
        sino_logger::setup();
        let GenesisConfigInfo {
            genesis_config,
            mint_keypair,
            ..
        } = create_genesis_config(10);
        let bank = Arc::new(Bank::new_no_wallclock_throttle_for_tests(&genesis_config));
        let start_hash = bank.last_blockhash();
        (mint_keypair, start_hash)
    }

    #[test]
    fn test_cost_model_instruction_cost() {
        let mut testee = CostModel::default();

        let known_key = Pubkey::from_str("known11111111111111111111111111111111111111").unwrap();
        testee.upsert_instruction_cost(&known_key, 100).unwrap();
        // find cost for known programs
        assert_eq!(100, testee.find_instruction_cost(&known_key));

        testee
            .upsert_instruction_cost(&bpf_loader::id(), 1999)
            .unwrap();
        assert_eq!(1999, testee.find_instruction_cost(&bpf_loader::id()));

        // unknown program is assigned with default cost
        assert_eq!(
            testee.instruction_execution_cost_table.get_mode(),
            testee.find_instruction_cost(
                &Pubkey::from_str("unknown111111111111111111111111111111111111").unwrap()
            )
        );
    }

    #[test]
    fn test_iterating_instruction_cost_by_program_keys() {
        sino_logger::setup();
        let mut testee = CostModel::default();

        let mut test_key_and_cost = HashMap::<Pubkey, u64>::new();
        (0u64..10u64).for_each(|n| {
            test_key_and_cost.insert(Pubkey::new_unique(), n);
        });

        test_key_and_cost.iter().for_each(|(key, cost)| {
            let _ = testee.upsert_instruction_cost(key, *cost).unwrap();
            info!("key {:?} cost {}", key, cost);
        });

        let keys = testee.get_program_keys();
        // verify each key has pre-set value
        keys.iter().for_each(|key| {
            let expected_cost = test_key_and_cost.get(key).unwrap();
            info!(
                "check key {:?} expect {} find {}",
                key,
                expected_cost,
                testee.find_instruction_cost(key)
            );
            assert_eq!(*expected_cost, testee.find_instruction_cost(key));
        });
    }

    #[test]
    fn test_cost_model_simple_transaction() {
        let (mint_keypair, start_hash) = test_setup();

        let keypair = Keypair::new();
        let simple_transaction = SanitizedTransaction::from_transaction_for_tests(
            system_transaction::transfer(&mint_keypair, &keypair.pubkey(), 2, start_hash),
        );
        debug!(
            "system_transaction simple_transaction {:?}",
            simple_transaction
        );

        // expected cost for one system transfer instructions
        let expected_execution_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap();

        let testee = CostModel::default();
        assert_eq!(
            (*expected_execution_cost, 0),
            testee.get_transaction_cost(&simple_transaction)
        );
    }

    #[test]
    fn test_cost_model_transaction_many_transfer_instructions() {
        let (mint_keypair, start_hash) = test_setup();

        let key1 = sdk::pubkey::new_rand();
        let key2 = sdk::pubkey::new_rand();
        let instructions =
            system_instruction::transfer_many(&mint_keypair.pubkey(), &[(key1, 1), (key2, 1)]);
        let message = Message::new(&instructions, Some(&mint_keypair.pubkey()));
        let tx = SanitizedTransaction::from_transaction_for_tests(Transaction::new(
            &[&mint_keypair],
            message,
            start_hash,
        ));
        debug!("many transfer transaction {:?}", tx);

        // expected cost for two system transfer instructions
        let program_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap();
        let expected_cost = program_cost * 2;

        let testee = CostModel::default();
        assert_eq!((expected_cost, 0), testee.get_transaction_cost(&tx));
    }

    #[test]
    fn test_cost_model_message_many_different_instructions() {
        let (mint_keypair, start_hash) = test_setup();

        // construct a transaction with multiple random instructions
        let key1 = sdk::pubkey::new_rand();
        let key2 = sdk::pubkey::new_rand();
        let prog1 = sdk::pubkey::new_rand();
        let prog2 = sdk::pubkey::new_rand();
        let instructions = vec![
            CompiledInstruction::new(3, &(), vec![0, 1]),
            CompiledInstruction::new(4, &(), vec![0, 2]),
        ];
        let tx = SanitizedTransaction::from_transaction_for_tests(
            Transaction::new_with_compiled_instructions(
                &[&mint_keypair],
                &[key1, key2],
                start_hash,
                vec![prog1, prog2],
                instructions,
            ),
        );
        debug!("many random transaction {:?}", tx);

        let testee = CostModel::default();
        let result = testee.get_transaction_cost(&tx);

        // expected cost for two random/unknown program is
        let expected_cost = testee.instruction_execution_cost_table.get_mode() * 2;
        assert_eq!((0, expected_cost), result);
    }

    #[test]
    fn test_cost_model_sort_message_accounts_by_type() {
        // construct a transaction with two random instructions with same signer
        let signer1 = Keypair::new();
        let signer2 = Keypair::new();
        let key1 = Pubkey::new_unique();
        let key2 = Pubkey::new_unique();
        let prog1 = Pubkey::new_unique();
        let prog2 = Pubkey::new_unique();
        let instructions = vec![
            CompiledInstruction::new(4, &(), vec![0, 2]),
            CompiledInstruction::new(5, &(), vec![1, 3]),
        ];
        let tx = SanitizedTransaction::from_transaction_for_tests(
            Transaction::new_with_compiled_instructions(
                &[&signer1, &signer2],
                &[key1, key2],
                Hash::new_unique(),
                vec![prog1, prog2],
                instructions,
            ),
        );

        let cost_model = CostModel::default();
        let tx_cost = cost_model.calculate_cost(&tx);
        assert_eq!(2 + 2, tx_cost.writable_accounts.len());
        assert_eq!(signer1.pubkey(), tx_cost.writable_accounts[0]);
        assert_eq!(signer2.pubkey(), tx_cost.writable_accounts[1]);
        assert_eq!(key1, tx_cost.writable_accounts[2]);
        assert_eq!(key2, tx_cost.writable_accounts[3]);
    }

    #[test]
    fn test_cost_model_insert_instruction_cost() {
        let key1 = Pubkey::new_unique();
        let cost1 = 100;

        let mut cost_model = CostModel::default();
        // Using default cost for unknown instruction
        assert_eq!(
            cost_model.instruction_execution_cost_table.get_mode(),
            cost_model.find_instruction_cost(&key1)
        );

        // insert instruction cost to table
        assert!(cost_model.upsert_instruction_cost(&key1, cost1).is_ok());

        // now it is known insturction with known cost
        assert_eq!(cost1, cost_model.find_instruction_cost(&key1));
    }

    #[test]
    fn test_cost_model_calculate_cost() {
        let (mint_keypair, start_hash) = test_setup();
        let tx = SanitizedTransaction::from_transaction_for_tests(system_transaction::transfer(
            &mint_keypair,
            &Keypair::new().pubkey(),
            2,
            start_hash,
        ));

        let expected_account_cost = WRITE_LOCK_UNITS * 2;
        let expected_execution_cost = BUILT_IN_INSTRUCTION_COSTS
            .get(&system_program::id())
            .unwrap();

        let cost_model = CostModel::default();
        let tx_cost = cost_model.calculate_cost(&tx);
        assert_eq!(expected_account_cost, tx_cost.write_lock_cost);
        assert_eq!(*expected_execution_cost, tx_cost.builtins_execution_cost);
        assert_eq!(2, tx_cost.writable_accounts.len());
    }

    #[test]
    fn test_cost_model_update_instruction_cost() {
        let key1 = Pubkey::new_unique();
        let cost1 = 100;
        let cost2 = 200;
        let updated_cost = (cost1 + cost2) / 2;

        let mut cost_model = CostModel::default();

        // insert instruction cost to table
        assert!(cost_model.upsert_instruction_cost(&key1, cost1).is_ok());
        assert_eq!(cost1, cost_model.find_instruction_cost(&key1));

        // update instruction cost
        assert!(cost_model.upsert_instruction_cost(&key1, cost2).is_ok());
        assert_eq!(updated_cost, cost_model.find_instruction_cost(&key1));
    }

    #[test]
    fn test_cost_model_can_be_shared_concurrently_with_rwlock() {
        let (mint_keypair, start_hash) = test_setup();
        // construct a transaction with multiple random instructions
        let key1 = sdk::pubkey::new_rand();
        let key2 = sdk::pubkey::new_rand();
        let prog1 = sdk::pubkey::new_rand();
        let prog2 = sdk::pubkey::new_rand();
        let instructions = vec![
            CompiledInstruction::new(3, &(), vec![0, 1]),
            CompiledInstruction::new(4, &(), vec![0, 2]),
        ];
        let tx = Arc::new(SanitizedTransaction::from_transaction_for_tests(
            Transaction::new_with_compiled_instructions(
                &[&mint_keypair],
                &[key1, key2],
                start_hash,
                vec![prog1, prog2],
                instructions,
            ),
        ));

        let number_threads = 10;
        let expected_account_cost = WRITE_LOCK_UNITS * 3;
        let cost1 = 100;
        let cost2 = 200;
        // execution cost can be either 2 * Default (before write) or cost1+cost2 (after write)

        let cost_model: Arc<RwLock<CostModel>> = Arc::new(RwLock::new(CostModel::default()));

        let thread_handlers: Vec<JoinHandle<()>> = (0..number_threads)
            .map(|i| {
                let cost_model = cost_model.clone();
                let tx = tx.clone();

                if i == 5 {
                    thread::spawn(move || {
                        let mut cost_model = cost_model.write().unwrap();
                        assert!(cost_model.upsert_instruction_cost(&prog1, cost1).is_ok());
                        assert!(cost_model.upsert_instruction_cost(&prog2, cost2).is_ok());
                    })
                } else {
                    thread::spawn(move || {
                        let cost_model = cost_model.write().unwrap();
                        let tx_cost = cost_model.calculate_cost(&tx);
                        assert_eq!(3, tx_cost.writable_accounts.len());
                        assert_eq!(expected_account_cost, tx_cost.write_lock_cost);
                    })
                }
            })
            .collect();

        for th in thread_handlers {
            th.join().unwrap();
        }
    }

    #[test]
    fn test_initialize_cost_table() {
        // build cost table
        let cost_table = vec![
            (Pubkey::new_unique(), 10),
            (Pubkey::new_unique(), 20),
            (Pubkey::new_unique(), 30),
        ];

        // init cost model
        let mut cost_model = CostModel::default();
        cost_model.initialize_cost_table(&cost_table);

        // verify
        for (id, cost) in cost_table.iter() {
            assert_eq!(*cost, cost_model.find_instruction_cost(id));
        }

        // verify built-in programs are not in bpf_costs
        assert!(cost_model
            .instruction_execution_cost_table
            .get_cost(&system_program::id())
            .is_none());
        assert!(cost_model
            .instruction_execution_cost_table
            .get_cost(&vote_program::id())
            .is_none());
    }
}
