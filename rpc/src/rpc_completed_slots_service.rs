use {
    crate::rpc_subscriptions::RpcSubscriptions,
    client::rpc_response::SlotUpdate,
    ledger::blockstore::CompletedSlotsReceiver,
    sdk::timing::timestamp,
    std::{
        sync::Arc,
        thread::{Builder, JoinHandle},
    },
};

pub struct RpcCompletedSlotsService;
impl RpcCompletedSlotsService {
    pub fn spawn(
        completed_slots_receiver: CompletedSlotsReceiver,
        rpc_subscriptions: Arc<RpcSubscriptions>,
    ) -> JoinHandle<()> {
        Builder::new()
            .name("sino-rpc-completed-slots-service".to_string())
            .spawn(move || {
                for slots in completed_slots_receiver.iter() {
                    for slot in slots {
                        rpc_subscriptions.notify_slot_update(SlotUpdate::Completed {
                            slot,
                            timestamp: timestamp(),
                        });
                    }
                }
            })
            .unwrap()
    }
}
