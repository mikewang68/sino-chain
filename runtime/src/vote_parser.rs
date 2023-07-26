use {
    sdk::{
        hash::Hash,
        program_utils::limited_deserialize,
        pubkey::Pubkey,
        transaction::{SanitizedTransaction, Transaction},
    },
    vote_program::{vote_instruction::VoteInstruction, vote_state::Vote},
};

pub type ParsedVote = (Pubkey, Vote, Option<Hash>);

// Used for filtering out votes from the transaction log collector
pub(crate) fn is_simple_vote_transaction(transaction: &SanitizedTransaction) -> bool {
    if transaction.message().instructions().len() == 1 {
        let (program_pubkey, instruction) = transaction
            .message()
            .program_instructions_iter()
            .next()
            .unwrap();
        if program_pubkey == &vote_program::id() {
            if let Ok(vote_instruction) = limited_deserialize::<VoteInstruction>(&instruction.data)
            {
                return matches!(
                    vote_instruction,
                    VoteInstruction::Vote(_) | VoteInstruction::VoteSwitch(_, _)
                );
            }
        }
    }
    false
}

// Used for locally forwarding processed vote transactions to consensus
pub fn parse_sanitized_vote_transaction(tx: &SanitizedTransaction) -> Option<ParsedVote> {
    // Check first instruction for a vote
    let message = tx.message();
    let (program_id, first_instruction) = message.program_instructions_iter().next()?;
    if !vote_program::check_id(program_id) {
        return None;
    }
    let first_account = usize::from(*first_instruction.accounts.first()?);
    let key = message.get_account_key(first_account)?;
    let (vote, switch_proof_hash) = parse_vote_instruction_data(&first_instruction.data)?;
    Some((*key, vote, switch_proof_hash))
}

// Used for parsing gossip vote transactions
pub fn parse_vote_transaction(tx: &Transaction) -> Option<ParsedVote> {
    // Check first instruction for a vote
    let message = tx.message();
    let first_instruction = message.instructions.first()?;
    let program_id_index = usize::from(first_instruction.program_id_index);
    let program_id = message.account_keys.get(program_id_index)?;
    if !vote_program::check_id(program_id) {
        return None;
    }
    let first_account = usize::from(*first_instruction.accounts.first()?);
    let key = message.account_keys.get(first_account)?;
    let (vote, switch_proof_hash) = parse_vote_instruction_data(&first_instruction.data)?;
    Some((*key, vote, switch_proof_hash))
}

fn parse_vote_instruction_data(vote_instruction_data: &[u8]) -> Option<(Vote, Option<Hash>)> {
    match limited_deserialize(vote_instruction_data).ok()? {
        VoteInstruction::Vote(vote) => Some((vote, None)),
        VoteInstruction::VoteSwitch(vote, hash) => Some((vote, Some(hash))),
        _ => None,
    }
}