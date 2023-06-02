use {
    crate::{stakes::Stakes, vote_account::VoteAccount},
    serde::{Deserialize, Serialize},
    sdk::{clock::Epoch, pubkey::Pubkey},
    std::{collections::HashMap, sync::Arc},
};

pub type NodeIdToVoteAccounts = HashMap<Pubkey, NodeVoteAccounts>;
pub type EpochAuthorizedVoters = HashMap<Pubkey, Pubkey>;

#[derive(Clone, Serialize, Debug, Deserialize, Default, PartialEq, Eq, AbiExample)]
pub struct NodeVoteAccounts {
    pub vote_accounts: Vec<Pubkey>,
    pub total_stake: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, AbiExample, PartialEq)]
pub struct EpochStakes {
    stakes: Arc<Stakes>,
    total_stake: u64,
    node_id_to_vote_accounts: Arc<NodeIdToVoteAccounts>,
    epoch_authorized_voters: Arc<EpochAuthorizedVoters>,
}

impl EpochStakes {
    pub fn new(stakes: &Stakes, leader_schedule_epoch: Epoch) -> Self {
        let epoch_vote_accounts = stakes.vote_accounts();
        let (total_stake, node_id_to_vote_accounts, epoch_authorized_voters) =
            Self::parse_epoch_vote_accounts(epoch_vote_accounts.as_ref(), leader_schedule_epoch);
        Self {
            stakes: Arc::new(stakes.clone()),
            total_stake,
            node_id_to_vote_accounts: Arc::new(node_id_to_vote_accounts),
            epoch_authorized_voters: Arc::new(epoch_authorized_voters),
        }
    }

    pub fn stakes(&self) -> &Stakes {
        &self.stakes
    }

    pub fn total_stake(&self) -> u64 {
        self.total_stake
    }

    pub fn node_id_to_vote_accounts(&self) -> &Arc<NodeIdToVoteAccounts> {
        &self.node_id_to_vote_accounts
    }

    pub fn epoch_authorized_voters(&self) -> &Arc<EpochAuthorizedVoters> {
        &self.epoch_authorized_voters
    }

    pub fn vote_account_stake(&self, vote_account: &Pubkey) -> u64 {
        self.stakes
            .vote_accounts()
            .get(vote_account)
            .map(|(stake, _)| *stake)
            .unwrap_or(0)
    }

    fn parse_epoch_vote_accounts(
        epoch_vote_accounts: &HashMap<Pubkey, (u64, VoteAccount)>,
        leader_schedule_epoch: Epoch,
    ) -> (u64, NodeIdToVoteAccounts, EpochAuthorizedVoters) {
        let mut node_id_to_vote_accounts: NodeIdToVoteAccounts = HashMap::new();
        let total_stake = epoch_vote_accounts
            .iter()
            .map(|(_, (stake, _))| stake)
            .sum();
        let epoch_authorized_voters = epoch_vote_accounts
            .iter()
            .filter_map(|(key, (stake, account))| {
                let vote_state = account.vote_state();
                let vote_state = match vote_state.as_ref() {
                    Err(_) => {
                        datapoint_warn!(
                            "parse_epoch_vote_accounts",
                            (
                                "warn",
                                format!("Unable to get vote_state from account {}", key),
                                String
                            ),
                        );
                        return None;
                    }
                    Ok(vote_state) => vote_state,
                };

                if *stake > 0 {
                    if let Some(authorized_voter) = vote_state
                        .authorized_voters()
                        .get_authorized_voter(leader_schedule_epoch)
                    {
                        let node_vote_accounts = node_id_to_vote_accounts
                            .entry(vote_state.node_pubkey)
                            .or_default();

                        node_vote_accounts.total_stake += stake;
                        node_vote_accounts.vote_accounts.push(*key);

                        Some((*key, authorized_voter))
                    } else {
                        None
                    }
                } else {
                    None
                }
            })
            .collect();
        (
            total_stake,
            node_id_to_vote_accounts,
            epoch_authorized_voters,
        )
    }
}
