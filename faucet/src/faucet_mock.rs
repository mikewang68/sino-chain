use {
    sdk::{
        hash::Hash, pubkey::Pubkey, signature::Keypair, system_transaction,
        transaction::Transaction,
    },
    std::{
        io::{Error, ErrorKind},
        net::SocketAddr,
    },
};

pub fn request_airdrop_transaction(
    _faucet_addr: &SocketAddr,
    _id: &Pubkey,
    wens: u64,
    _blockhash: Hash,
) -> Result<Transaction, Error> {
    if wens == 0 {
        Err(Error::new(ErrorKind::Other, "Airdrop failed"))
    } else {
        let key = Keypair::new();
        let to = sdk::pubkey::new_rand();
        let blockhash = Hash::default();
        let tx = system_transaction::transfer(&key, &to, wens, blockhash);
        Ok(tx)
    }
}