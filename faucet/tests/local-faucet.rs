use {
    faucet::faucet::{request_airdrop_transaction, run_local_faucet},
    sdk::{
        hash::Hash,
        message::Message,
        signature::{Keypair, Signer},
        system_instruction,
        transaction::Transaction,
    },
};

#[test]
fn test_local_faucet() {
    let keypair = Keypair::new();
    let to = sdk::pubkey::new_rand();
    let wens = 50;
    let blockhash = Hash::new(to.as_ref());
    let create_instruction = system_instruction::transfer(&keypair.pubkey(), &to, wens);
    let message = Message::new(&[create_instruction], Some(&keypair.pubkey()));
    let expected_tx = Transaction::new(&[&keypair], message, blockhash);

    let faucet_addr = run_local_faucet(keypair, None);

    let result = request_airdrop_transaction(&faucet_addr, &to, wens, blockhash);
    assert_eq!(expected_tx, result.unwrap());
}