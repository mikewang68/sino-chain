// trace_macros!(true);
use std::{collections::BTreeMap, time::Instant};

use criterion::{criterion_group, criterion_main, Criterion};
use dashmap::DashMap;
use primitive_types::H256;
use rand::prelude::*;
use rocksdb_lib::{ColumnFamilyDescriptor, Options, DB};
use tempfile::tempdir;
use triedb::{
    gc::TrieCollection,
    rocksdb::{RocksDatabaseHandleGC, RocksHandle},
    MemoryTrieMut, TrieMut,
};

// Amount of entries to be added to collection before benching
const PREP_SIZE: usize = 1000;
const PREP_SEED: [u8; 32] = [57_u8; 32];

// Amount of entries to be added to collection during benching
const BENCH_AMOUNT: usize = 200;
const BENCH_SEED: [u8; 32] = [42_u8; 32];

// usually we store two types of data:
// 1. account, with size = 2xHASH+2xU256
// 2. storage = HASH
// so 150 bytes is realistic assumption.
const VALUE_SIZE_BYTES: usize = 150;

fn rand_collection(
    seed: [u8; 32],
    size: usize,
) -> impl Iterator<Item = (H256, [u8; VALUE_SIZE_BYTES])> {
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let mut ret = Vec::with_capacity(size);

    for _ in 0..size {
        let key = {
            let mut key = [0u8; 32];
            rng.fill_bytes(&mut key);
            H256(key)
        };

        let value = {
            let mut value = [0u8; VALUE_SIZE_BYTES];
            rng.fill_bytes(&mut value);
            value
        };

        ret.push((key, value));
    }

    ret.into_iter()
}

fn rand_choose(
    seed: [u8; 32],
    collection: Vec<(H256, [u8; VALUE_SIZE_BYTES])>,
    num_random: usize,
    num_from_collection: usize,
) -> Vec<H256> {
    let mut rng = rand::rngs::StdRng::from_seed(seed);

    let random = rand_collection(seed, num_random).map(|(k, _)| k);

    let from_collection: Vec<_> = collection
        .choose_multiple(&mut rng, num_from_collection)
        .map(|(k, _)| *k)
        .collect();

    from_collection.into_iter().chain(random).collect()
}

fn bench_insert_backends(
    c: &mut Criterion,
    (bench_seed, setup_seed): ([u8; 32], [u8; 32]),
    (bench_amount, setup_amount): (usize, usize),
) {
    //TODO: Replace it, like in get, choose random values from collections to replace.
    let test_data: Vec<_> = rand_collection(bench_seed, bench_amount).collect();

    c.bench_function("bench insert BTreeMap", |b| {
        b.iter_batched(
            || {
                (
                    test_data.clone(),
                    rand_collection(setup_seed, setup_amount).collect::<BTreeMap<_, _>>(),
                )
            },
            |(test_data, mut sut)| {
                for (key, value) in test_data {
                    sut.insert(key, value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench insert DashMap", |b| {
        b.iter_batched(
            || {
                (
                    test_data.clone(),
                    rand_collection(setup_seed, setup_amount).collect::<DashMap<_, _>>(),
                )
            },
            |(test_data, sut)| {
                for (key, value) in test_data {
                    sut.insert(key, value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench insert RocksDB", |b| {
        let dir = tempdir().unwrap();
        let sut = DB::open_default(&dir).unwrap();

        let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();

        for (key, value) in prep {
            sut.put(key, value).unwrap();
        }

        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.put(key, value).unwrap();
                }
            },
            criterion::BatchSize::SmallInput,
        );
        drop(sut);
        DB::destroy(&Options::default(), &dir).unwrap();
    });

    c.bench_function("bench insert MemoryTrieMut", |b| {
        let mut sut = MemoryTrieMut::default();

        let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();

        for (key, value) in prep {
            sut.insert(key.as_bytes(), &value);
        }

        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for (key, value) in test_data {
                    sut.insert(key.as_bytes(), &value);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench insert TrieCollection<Mem>", |b| {
        use triedb::empty_trie_hash;
        use triedb::gc::MapWithCounterCached;

        let handle = MapWithCounterCached::default();

        let collection = TrieCollection::new(handle);

        b.iter_custom(|num_iters| {
            let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();
            let mut trie = collection.trie_for(empty_trie_hash());

            for (key, value) in prep {
                trie.insert(key.as_bytes(), &value);
            }

            let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
            let root = collection.apply_increase(patch, |_| vec![]);

            let start = Instant::now();
            for _iter in 0..num_iters {
                let mut trie = collection.trie_for(root.root);
                // Start benchmark
                for (key, value) in &test_data {
                    trie.insert(key.as_bytes(), &*value);
                }

                let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
                let _root = collection.apply_increase(patch, |_| vec![]);
            }

            start.elapsed()
        });
    });

    c.bench_function("bench insert TrieCollection<Rocks>", |b| {
        use triedb::empty_trie_hash;
        use triedb::rocksdb::{merge_counter, DB};

        fn default_opts() -> Options {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            opts
        }

        fn counter_cf_opts() -> Options {
            let mut opts = default_opts();
            opts.set_merge_operator_associative("inc_counter", merge_counter);
            opts
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let handle = RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf));

        let collection = TrieCollection::new(handle);

        b.iter_custom(|num_iters| {
            let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();
            let mut trie = collection.trie_for(empty_trie_hash());

            for (key, value) in prep {
                trie.insert(key.as_bytes(), &value);
            }

            let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
            let root = collection.apply_increase(patch, |_| vec![]);

            let start = Instant::now();
            for _iter in 0..num_iters {
                let mut trie = collection.trie_for(root.root);
                // Start benchmark
                for (key, value) in &test_data {
                    trie.insert(key.as_bytes(), &*value);
                }

                let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
                let _root = collection.apply_increase(patch, |_| vec![]);
            }

            start.elapsed()
        });
    });
}

fn bench_get_backends(
    c: &mut Criterion,
    (bench_seed, setup_seed): ([u8; 32], [u8; 32]),
    (num_exist, num_random, setup_amount): (usize, usize, usize),
) {
    let setup_data: Vec<_> = rand_collection(setup_seed, setup_amount).collect();

    let test_data = rand_choose(bench_seed, setup_data.clone(), num_random, num_exist);

    c.bench_function("bench get BTreeMap", |b| {
        b.iter_batched(
            || {
                (
                    test_data.clone(),
                    setup_data.clone().into_iter().collect::<BTreeMap<_, _>>(),
                )
            },
            |(test_data, sut)| {
                for key in test_data {
                    let _ = sut.get(&key);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench get DashMap", |b| {
        b.iter_batched(
            || {
                (
                    test_data.clone(),
                    setup_data.clone().into_iter().collect::<DashMap<_, _>>(),
                )
            },
            |(test_data, sut)| {
                for key in test_data {
                    let _ = sut.get(&key);
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench get RocksDB", |b| {
        let dir = tempdir().unwrap();
        let sut = DB::open_default(&dir).unwrap();

        for (key, value) in &setup_data {
            sut.put(key, value).unwrap();
        }

        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for key in test_data {
                    let _ = sut.get(key.as_bytes());
                }
            },
            criterion::BatchSize::SmallInput,
        );
        drop(sut);
        DB::destroy(&Options::default(), &dir).unwrap();
    });

    c.bench_function("bench get MemoryTrieMut", |b| {
        let mut sut = MemoryTrieMut::default();

        let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();

        for (key, value) in prep {
            sut.insert(key.as_bytes(), &value);
        }

        b.iter_batched(
            || test_data.clone(),
            |test_data| {
                for key in test_data {
                    let _ = sut.get(key.as_bytes());
                }
            },
            criterion::BatchSize::SmallInput,
        )
    });

    c.bench_function("bench get TrieCollection<Mem>", |b| {
        use triedb::empty_trie_hash;
        use triedb::gc::MapWithCounterCached;

        let handle = MapWithCounterCached::default();

        let collection = TrieCollection::new(handle);

        b.iter_custom(|num_iters| {
            let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();
            let mut trie = collection.trie_for(empty_trie_hash());

            for (key, value) in prep {
                trie.insert(key.as_bytes(), &value);
            }

            let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
            let root = collection.apply_increase(patch, |_| vec![]);

            let start = Instant::now();
            for _iter in 0..num_iters {
                let trie = collection.trie_for(root.root);
                // Start benchmark
                for key in &test_data {
                    let _ = trie.get(key.as_bytes());
                }

                let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
                let _root = collection.apply_increase(patch, |_| vec![]);
            }

            start.elapsed()
        });
    });

    c.bench_function("bench get TrieCollection<Rocks>", |b| {
        use triedb::empty_trie_hash;
        use triedb::rocksdb::{merge_counter, DB};

        fn default_opts() -> Options {
            let mut opts = Options::default();
            opts.create_if_missing(true);
            opts.create_missing_column_families(true);
            opts
        }

        fn counter_cf_opts() -> Options {
            let mut opts = default_opts();
            opts.set_merge_operator_associative("inc_counter", merge_counter);
            opts
        }

        let dir = tempdir().unwrap();
        let counter_cf = ColumnFamilyDescriptor::new("counter", counter_cf_opts());
        let db = DB::open_cf_descriptors(&default_opts(), &dir, [counter_cf]).unwrap();

        let cf = db.cf_handle("counter").unwrap();

        let handle = RocksHandle::new(RocksDatabaseHandleGC::new(&db, cf));

        let collection = TrieCollection::new(handle);

        b.iter_custom(|num_iters| {
            let prep: Vec<_> = rand_collection(setup_seed, setup_amount).collect();
            let mut trie = collection.trie_for(empty_trie_hash());

            for (key, value) in prep {
                trie.insert(key.as_bytes(), &value);
            }

            let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
            let root = collection.apply_increase(patch, |_| vec![]);

            let start = Instant::now();
            for _iter in 0..num_iters {
                let trie = collection.trie_for(root.root);
                // Start benchmark
                for key in &test_data {
                    let _ = trie.get(key.as_bytes());
                }

                let patch = trie.into_patch(); // FIXME: get patch without consuming `self`
                let _root = collection.apply_increase(patch, |_| vec![]);
            }

            start.elapsed()
        });
    });
}

fn bench_db_backends(c: &mut Criterion) {
    bench_get_backends(
        c,
        (BENCH_SEED, PREP_SEED),
        (BENCH_AMOUNT / 2, BENCH_AMOUNT / 2, PREP_SIZE),
    );
    bench_insert_backends(c, (BENCH_SEED, PREP_SEED), (BENCH_AMOUNT, PREP_SIZE))
}

criterion_group!(benches, bench_db_backends);
criterion_main!(benches);
