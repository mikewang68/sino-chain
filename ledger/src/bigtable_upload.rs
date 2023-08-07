use {
    crate::blockstore::Blockstore,
    log::*,
    measure::measure::Measure,
    sdk::clock::Slot,
    std::{
        collections::HashSet,
        result::Result,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        time::Duration,
    },
};
use tokio::time::sleep;

// Attempt to upload this many blocks in parallel
const NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL: usize = 32;

// Read up to this many blocks from blockstore before blocking on the upload process
const BLOCK_READ_AHEAD_DEPTH: usize = NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL * 2;

pub async fn upload_confirmed_blocks(
    blockstore: Arc<Blockstore>,
    bigtable: storage_bigtable::LedgerStorage,
    starting_slot: Slot,
    ending_slot: Option<Slot>,
    force_reupload: bool,
    exit: Arc<AtomicBool>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut measure = Measure::start("entire upload");

    info!("Loading ledger slots starting at {}...", starting_slot);
    let blockstore_slots: Vec<_> = blockstore
        .slot_meta_iterator(starting_slot)
        .map_err(|err| {
            format!(
                "Failed to load entries starting from slot {}: {:?}",
                starting_slot, err
            )
        })?
        .filter_map(|(slot, _slot_meta)| {
            if let Some(ending_slot) = &ending_slot {
                if slot > *ending_slot {
                    return None;
                }
            }
            Some(slot)
        })
        .collect();

    if blockstore_slots.is_empty() {
        return Err(format!(
            "Ledger has no slots from {} to {:?}",
            starting_slot, ending_slot
        )
        .into());
    }

    info!(
        "Found {} slots in the range ({}, {})",
        blockstore_slots.len(),
        blockstore_slots.first().unwrap(),
        blockstore_slots.last().unwrap()
    );

    // Gather the blocks that are already present in bigtable, by slot
    let bigtable_slots = if !force_reupload {
        let mut bigtable_slots = vec![];
        let first_blockstore_slot = *blockstore_slots.first().unwrap();
        let last_blockstore_slot = *blockstore_slots.last().unwrap();
        info!(
            "Loading list of bigtable blocks between slots {} and {}...",
            first_blockstore_slot, last_blockstore_slot
        );

        let mut start_slot = *blockstore_slots.first().unwrap();
        while start_slot <= last_blockstore_slot {
            let mut next_bigtable_slots = loop {
                match bigtable.get_confirmed_blocks(start_slot, 1000).await {
                    Ok(slots) => break slots,
                    Err(err) => {
                        error!("get_confirmed_blocks for {} failed: {:?}", start_slot, err);
                        // Consider exponential backoff...
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            };
            if next_bigtable_slots.is_empty() {
                break;
            }
            bigtable_slots.append(&mut next_bigtable_slots);
            start_slot = bigtable_slots.last().unwrap() + 1;
        }
        bigtable_slots
            .into_iter()
            .filter(|slot| *slot <= last_blockstore_slot)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // The blocks that still need to be uploaded is the difference between what's already in the
    // bigtable and what's in blockstore...
    let blocks_to_upload = {
        let blockstore_slots = blockstore_slots.iter().cloned().collect::<HashSet<_>>();
        let bigtable_slots = bigtable_slots.into_iter().collect::<HashSet<_>>();

        let mut blocks_to_upload = blockstore_slots
            .difference(&bigtable_slots)
            .cloned()
            .collect::<Vec<_>>();
        blocks_to_upload.sort_unstable();
        blocks_to_upload
    };

    if blocks_to_upload.is_empty() {
        info!("No blocks need to be uploaded to bigtable");
        return Ok(());
    }
    info!(
        "{} blocks to be uploaded to the bucket in the range ({}, {})",
        blocks_to_upload.len(),
        blocks_to_upload.first().unwrap(),
        blocks_to_upload.last().unwrap()
    );

    // Load the blocks out of blockstore in a separate thread to allow for concurrent block uploading
    let (_loader_thread, receiver) = {
        let exit = exit.clone();

        let (sender, receiver) = std::sync::mpsc::sync_channel(BLOCK_READ_AHEAD_DEPTH);
        (
            std::thread::spawn(move || {
                let mut measure = Measure::start("block loader thread");
                for (i, slot) in blocks_to_upload.iter().enumerate() {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let _ = match blockstore.get_rooted_block(*slot, true) {
                        Ok(confirmed_block) => sender.send((*slot, Some(confirmed_block))),
                        Err(err) => {
                            warn!(
                                "Failed to get load confirmed block from slot {}: {:?}",
                                slot, err
                            );
                            sender.send((*slot, None))
                        }
                    };

                    if i > 0 && i % NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL == 0 {
                        info!(
                            "{}% of blocks processed ({}/{})",
                            i * 100 / blocks_to_upload.len(),
                            i,
                            blocks_to_upload.len()
                        );
                    }
                }
                measure.stop();
                info!("{} to load {} blocks", measure, blocks_to_upload.len());
            }),
            receiver,
        )
    };

    let mut failures = 0;
    use futures::stream::StreamExt;

    let mut stream =
        tokio_stream::iter(receiver.into_iter()).chunks(NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL);

    while let Some(blocks) = stream.next().await {
        if exit.load(Ordering::Relaxed) {
            break;
        }

        let mut measure_upload = Measure::start("Upload");
        let mut num_blocks = blocks.len();
        info!("Preparing the next {} blocks for upload", num_blocks);

        let uploads = blocks.into_iter().filter_map(|(slot, block)| match block {
            None => {
                num_blocks -= 1;
                None
            }
            Some(confirmed_block) => Some(bigtable.upload_confirmed_block(slot, confirmed_block)),
        });

        for result in futures::future::join_all(uploads).await {
            if result.is_err() {
                error!("upload_confirmed_block() failed: {:?}", result.err());
                failures += 1;
            }
        }

        measure_upload.stop();
        info!("{} for {} blocks", measure_upload, num_blocks);
    }

    measure.stop();
    info!("{}", measure);
    if failures > 0 {
        Err(format!("Incomplete upload, {} operations failed", failures).into())
    } else {
        Ok(())
    }
}

pub async fn upload_evm_confirmed_blocks(
    blockstore: Arc<Blockstore>,
    bigtable: storage_bigtable::LedgerStorage,
    starting_block: evm_state::BlockNum,
    ending_block: Option<evm_state::BlockNum>,
    push_not_confirmed: bool,
    force_reupload: bool,
    exit: Arc<AtomicBool>,
) -> Result<evm_state::BlockNum, Box<dyn std::error::Error>> {
    let mut measure = Measure::start("entire upload");

    info!(
        "Loading evm ledger blocks starting at {}...",
        starting_block
    );
    let mut block_headers: Vec<_> = blockstore
        .evm_blocks_iterator(starting_block)
        .map_err(|err| {
            format!(
                "Failed to load entries starting from slot {}: {:?}",
                starting_block, err
            )
        })?
        .filter_map(|((block_num, _slot), _block)| {
            if let Some(ending_block) = &ending_block {
                if block_num > *ending_block {
                    return None;
                }
            }
            Some(block_num)
        })
        .collect();

    // evm_blocks_iterator can return multiple blocks with same block_num, remove duplicates.
    block_headers.dedup();

    if block_headers.is_empty() {
        return Err(format!(
            "Ledger has no blocks from {} to {:?}",
            starting_block, ending_block
        )
        .into());
    }

    info!(
        "Found {} slots in the range ({}, {})",
        block_headers.len(),
        block_headers.first().unwrap(),
        block_headers.last().unwrap()
    );

    // Gather the blocks that are already present in bigtable, by slot
    let bigtable_slots = if !force_reupload {
        let mut bigtable_blocks = vec![];
        let first_blockstore_block = *block_headers.first().unwrap();
        let last_blockstore_block = *block_headers.last().unwrap();
        info!(
            "Loading list of bigtable evm blocks between blocks {} and {}...",
            first_blockstore_block, last_blockstore_block
        );

        let mut start_block = *block_headers.first().unwrap();
        while start_block <= last_blockstore_block {
            let mut next_bigtable_blocks = loop {
                match bigtable.get_evm_confirmed_blocks(start_block, 1000).await {
                    Ok(slots) => break slots,
                    Err(err) => {
                        error!(
                            "get_evm_confirmed_blocks for {} failed: {:?}",
                            start_block, err
                        );
                        // Consider exponential backoff...
                        sleep(Duration::from_secs(2)).await;
                    }
                }
            };
            if next_bigtable_blocks.is_empty() {
                break;
            }
            bigtable_blocks.append(&mut next_bigtable_blocks);
            start_block = bigtable_blocks.last().unwrap() + 1;
        }
        bigtable_blocks
            .into_iter()
            .filter(|slot| *slot <= last_blockstore_block)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    // The blocks that still need to be uploaded is the difference between what's already in the
    // bigtable and what's in blockstore...
    let blocks_to_upload = {
        let block_headers = block_headers.iter().cloned().collect::<HashSet<_>>();
        let bigtable_slots = bigtable_slots.into_iter().collect::<HashSet<_>>();

        let mut blocks_to_upload = block_headers
            .difference(&bigtable_slots)
            .cloned()
            .collect::<Vec<_>>();
        blocks_to_upload.sort_unstable();
        blocks_to_upload
    };

    if blocks_to_upload.is_empty() {
        info!("No blocks need to be uploaded to bigtable");
        return Ok(0);
    }
    info!(
        "{} blocks to be uploaded to the bucket in the range ({}, {})",
        blocks_to_upload.len(),
        blocks_to_upload.first().unwrap(),
        blocks_to_upload.last().unwrap()
    );

    // Load the blocks out of blockstore in a separate thread to allow for concurrent block uploading
    let (_loader_thread, receiver) = {
        let exit = exit.clone();

        let (sender, receiver) = std::sync::mpsc::sync_channel(BLOCK_READ_AHEAD_DEPTH);
        (
            std::thread::spawn(move || {
                let mut measure = Measure::start("block loader thread");
                for (i, block_num) in blocks_to_upload.iter().enumerate() {
                    if exit.load(Ordering::Relaxed) {
                        break;
                    }

                    let _ = match blockstore.get_evm_block(*block_num) {
                        Ok(confirmed_block) => sender.send((*block_num, Some(confirmed_block))),
                        Err(err) => {
                            warn!(
                                "Failed to get load evm confirmed block from slot {}: {:?}",
                                block_num, err
                            );
                            sender.send((*block_num, None))
                        }
                    };

                    if i > 0 && i % NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL == 0 {
                        info!(
                            "{}% of blocks processed ({}/{})",
                            i * 100 / blocks_to_upload.len(),
                            i,
                            blocks_to_upload.len()
                        );
                    }
                }
                measure.stop();
                info!("{} to load {} blocks", measure, blocks_to_upload.len());
            }),
            receiver,
        )
    };

    let mut failures = 0;
    let mut not_confirmed_blocks = 0;
    use futures::stream::StreamExt;

    let mut stream =
        tokio_stream::iter(receiver.into_iter()).chunks(NUM_BLOCKS_TO_UPLOAD_IN_PARALLEL);

    while let Some(blocks) = stream.next().await {
        if exit.load(Ordering::Relaxed) {
            break;
        }

        let mut measure_upload = Measure::start("Upload");
        let mut num_blocks = blocks.len();
        info!("Preparing the next {} blocks for upload", num_blocks);

        let uploads = blocks
            .into_iter()
            .filter_map(|(block_num, confirmed_block)| match confirmed_block {
                None => {
                    num_blocks -= 1;
                    None
                }
                Some((confirmed_block, true)) => {
                    Some(bigtable.upload_evm_block(block_num, confirmed_block))
                }
                Some((confirmed_block, false)) => {
                    debug!(
                        "Foind evm block = {:?}, that is still not confirmed, push_not_confirmed={}.",
                        block_num, push_not_confirmed
                    );
                    if push_not_confirmed {
                        Some(bigtable.upload_evm_block(block_num, confirmed_block))
                    } else {
                        not_confirmed_blocks += 1;
                        None
                    }
                }
            });

        for result in futures::future::join_all(uploads).await {
            if result.is_err() {
                error!("upload_confirmed_block() failed: {:?}", result.err());
                failures += 1;
            }
        }

        measure_upload.stop();
        info!("{} for {} blocks", measure_upload, num_blocks);
    }

    measure.stop();
    info!("{}", measure);
    if failures > 0 {
        Err(format!("Incomplete upload, {} operations failed", failures).into())
    } else {
        Ok(not_confirmed_blocks)
    }
}
