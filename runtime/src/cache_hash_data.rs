//! Cached data for hashing accounts
use {
    crate::{
        accounts_hash::CalculateHashIntermediate,
        pubkey_bins::PubkeyBinCalculator24,
    },
    log::*,
    memmap2::MmapMut,
    measure::measure::Measure,
    std::{
        collections::HashSet,
        fs::{self, remove_file, OpenOptions},
        io::{Seek, SeekFrom, Write},
        path::{Path, PathBuf},
        sync::{Arc, Mutex},
    },
};

#[repr(C)]
pub struct Header {
    count: usize,
}

struct CacheHashDataFile {
    cell_size: u64,
    mmap: MmapMut,
    capacity: u64,
}

impl CacheHashDataFile {
    fn get_mut<T: Sized>(&mut self, ix: u64) -> &mut T {
        let start = (ix * self.cell_size) as usize + std::mem::size_of::<Header>();
        let end = start + std::mem::size_of::<T>();
        assert!(
            end <= self.capacity as usize,
            "end: {}, capacity: {}, ix: {}, cell size: {}",
            end,
            self.capacity,
            ix,
            self.cell_size
        );
        let item_slice: &[u8] = &self.mmap[start..end];
        unsafe {
            let item = item_slice.as_ptr() as *mut T;
            &mut *item
        }
    }

    fn get_header_mut(&mut self) -> &mut Header {
        let start = 0_usize;
        let end = start + std::mem::size_of::<Header>();
        let item_slice: &[u8] = &self.mmap[start..end];
        unsafe {
            let item = item_slice.as_ptr() as *mut Header;
            &mut *item
        }
    }

    fn new_map(file: &Path, capacity: u64) -> Result<MmapMut, std::io::Error> {
        let mut data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(file)?;

        // Theoretical performance optimization: write a zero to the end of
        // the file so that we won't have to resize it later, which may be
        // expensive.
        data.seek(SeekFrom::Start(capacity - 1)).unwrap();
        data.write_all(&[0]).unwrap();
        data.seek(SeekFrom::Start(0)).unwrap();
        data.flush().unwrap();
        Ok(unsafe { MmapMut::map_mut(&data).unwrap() })
    }

    fn load_map(file: &Path) -> Result<MmapMut, std::io::Error> {
        let data = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .open(file)?;

        Ok(unsafe { MmapMut::map_mut(&data).unwrap() })
    }
}

pub type EntryType = CalculateHashIntermediate;
pub type SavedType = Vec<Vec<EntryType>>;
pub type SavedTypeSlice = [Vec<EntryType>];

pub type PreExistingCacheFiles = HashSet<String>;
pub struct CacheHashData {
    cache_folder: PathBuf,
    pre_existing_cache_files: Arc<Mutex<PreExistingCacheFiles>>,
    pub stats: Arc<Mutex<CacheHashDataStats>>,
}

impl CacheHashData {
    fn load_internal<P: AsRef<Path> + std::fmt::Debug>(
        &self,
        file_name: &P,
        accumulator: &mut SavedType,
        start_bin_index: usize,
        bin_calculator: &PubkeyBinCalculator24,
        stats: &mut CacheHashDataStats,
    ) -> Result<(), std::io::Error> {
        let mut m = Measure::start("overall");
        let path = self.cache_folder.join(file_name);
        let file_len = std::fs::metadata(path.clone())?.len();
        let mut m1 = Measure::start("read_file");
        let mmap = CacheHashDataFile::load_map(&path)?;
        m1.stop();
        stats.read_us = m1.as_us();
        let header_size = std::mem::size_of::<Header>() as u64;
        if file_len < header_size {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }

        let cell_size = std::mem::size_of::<EntryType>() as u64;
        let mut cache_file = CacheHashDataFile {
            mmap,
            cell_size,
            capacity: 0,
        };
        let header = cache_file.get_header_mut();
        let entries = header.count;

        let capacity = cell_size * (entries as u64) + header_size;
        if file_len < capacity {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        cache_file.capacity = capacity;
        assert_eq!(
            capacity, file_len,
            "expected: {}, len on disk: {} {:?}, entries: {}, cell_size: {}",
            capacity, file_len, path, entries, cell_size
        );

        stats.total_entries = entries;
        stats.cache_file_size += capacity as usize;

        let file_name_lookup = file_name.as_ref().to_str().unwrap().to_string();
        let found = self
            .pre_existing_cache_files
            .lock()
            .unwrap()
            .remove(&file_name_lookup);
        if !found {
            info!(
                "tried to mark {:?} as used, but it wasn't in the set, one example: {:?}",
                file_name_lookup,
                self.pre_existing_cache_files.lock().unwrap().iter().next()
            );
        }

        stats.loaded_from_cache += 1;
        stats.entries_loaded_from_cache += entries;
        let mut m2 = Measure::start("decode");
        for i in 0..entries {
            let d = cache_file.get_mut::<EntryType>(i as u64);
            let mut pubkey_to_bin_index = bin_calculator.bin_from_pubkey(&d.pubkey);
            assert!(
                pubkey_to_bin_index >= start_bin_index,
                "{}, {}",
                pubkey_to_bin_index,
                start_bin_index
            ); // this would indicate we put a pubkey in too high of a bin
            pubkey_to_bin_index -= start_bin_index;
            accumulator[pubkey_to_bin_index].push(d.clone()); // may want to avoid clone here
        }

        m2.stop();
        stats.decode_us += m2.as_us();
        m.stop();
        stats.load_us += m.as_us();
        Ok(())
    }

    pub fn load<P: AsRef<Path> + std::fmt::Debug>(
        &self,
        file_name: &P,
        accumulator: &mut SavedType,
        start_bin_index: usize,
        bin_calculator: &PubkeyBinCalculator24,
    ) -> Result<(), std::io::Error> {
        let mut stats = CacheHashDataStats::default();
        let result = self.load_internal(
            file_name,
            accumulator,
            start_bin_index,
            bin_calculator,
            &mut stats,
        );
        self.stats.lock().unwrap().merge(&stats);
        result
    }

    pub fn save(&self, file_name: &Path, data: &SavedTypeSlice) -> Result<(), std::io::Error> {
        let mut stats = CacheHashDataStats::default();
        let result = self.save_internal(file_name, data, &mut stats);
        self.stats.lock().unwrap().merge(&stats);
        result
    }

    pub fn save_internal(
        &self,
        file_name: &Path,
        data: &SavedTypeSlice,
        stats: &mut CacheHashDataStats,
    ) -> Result<(), std::io::Error> {
        let mut m = Measure::start("save");
        let cache_path = self.cache_folder.join(file_name);
        let create = true;
        if create {
            let _ignored = remove_file(&cache_path);
        }
        let cell_size = std::mem::size_of::<EntryType>() as u64;
        let mut m1 = Measure::start("create save");
        let entries = data
            .iter()
            .map(|x: &Vec<EntryType>| x.len())
            .collect::<Vec<_>>();
        let entries = entries.iter().sum::<usize>();
        let capacity = cell_size * (entries as u64) + std::mem::size_of::<Header>() as u64;

        let mmap = CacheHashDataFile::new_map(&cache_path, capacity)?;
        m1.stop();
        stats.create_save_us += m1.as_us();
        let mut cache_file = CacheHashDataFile {
            mmap,
            cell_size,
            capacity,
        };

        let mut header = cache_file.get_header_mut();
        header.count = entries;

        stats.cache_file_size = capacity as usize;
        stats.total_entries = entries;

        let mut m2 = Measure::start("write_to_mmap");
        let mut i = 0;
        data.iter().for_each(|x| {
            x.iter().for_each(|item| {
                let d = cache_file.get_mut::<EntryType>(i as u64);
                i += 1;
                *d = item.clone();
            })
        });
        assert_eq!(i, entries);
        m2.stop();
        stats.write_to_mmap_us += m2.as_us();
        m.stop();
        stats.save_us += m.as_us();
        stats.saved_to_cache += 1;
        Ok(())
    }

    fn get_cache_root_path<P: AsRef<Path>>(parent_folder: &P) -> PathBuf {
        parent_folder.as_ref().join("calculate_accounts_hash_cache")
    }

    pub fn new<P: AsRef<Path> + std::fmt::Debug>(parent_folder: &P) -> CacheHashData {
        let cache_folder = Self::get_cache_root_path(parent_folder);

        std::fs::create_dir_all(cache_folder.clone())
            .unwrap_or_else(|_| panic!("error creating cache dir: {:?}", cache_folder));

        let result = CacheHashData {
            cache_folder,
            pre_existing_cache_files: Arc::new(Mutex::new(PreExistingCacheFiles::default())),
            stats: Arc::new(Mutex::new(CacheHashDataStats::default())),
        };

        result.get_cache_files();
        result
    }

    fn get_cache_files(&self) {
        if self.cache_folder.is_dir() {
            let dir = fs::read_dir(self.cache_folder.clone());
            if let Ok(dir) = dir {
                let mut pre_existing = self.pre_existing_cache_files.lock().unwrap();
                for entry in dir.flatten() {
                    if let Some(name) = entry.path().file_name() {
                        pre_existing.insert(name.to_str().unwrap().to_string());
                    }
                }
                self.stats.lock().unwrap().cache_file_count += pre_existing.len();
            }
        }
    }
}

// Cached data for hashing accounts
#[derive(Default, Debug)]
pub struct CacheHashDataStats {
    pub cache_file_size: usize,
    pub cache_file_count: usize,
    pub total_entries: usize,
    pub loaded_from_cache: usize,
    pub entries_loaded_from_cache: usize,
    pub save_us: u64,
    pub saved_to_cache: usize,
    pub write_to_mmap_us: u64,
    pub create_save_us: u64,
    pub load_us: u64,
    pub read_us: u64,
    pub decode_us: u64,
    pub merge_us: u64,
    pub unused_cache_files: usize,
}

impl CacheHashDataStats {
    pub fn merge(&mut self, other: &CacheHashDataStats) {
        self.cache_file_size += other.cache_file_size;
        self.total_entries += other.total_entries;
        self.loaded_from_cache += other.loaded_from_cache;
        self.entries_loaded_from_cache += other.entries_loaded_from_cache;
        self.load_us += other.load_us;
        self.read_us += other.read_us;
        self.decode_us += other.decode_us;
        self.save_us += other.save_us;
        self.saved_to_cache += other.saved_to_cache;
        self.create_save_us += other.create_save_us;
        self.cache_file_count += other.cache_file_count;
        self.write_to_mmap_us += other.write_to_mmap_us;
        self.unused_cache_files += other.unused_cache_files;
    }

    pub fn report(&self) {
        datapoint_info!(
            "cache_hash_data_stats",
            ("cache_file_size", self.cache_file_size, i64),
            ("cache_file_count", self.cache_file_count, i64),
            ("total_entries", self.total_entries, i64),
            ("loaded_from_cache", self.loaded_from_cache, i64),
            ("saved_to_cache", self.saved_to_cache, i64),
            (
                "entries_loaded_from_cache",
                self.entries_loaded_from_cache,
                i64
            ),
            ("save_us", self.save_us, i64),
            ("write_to_mmap_us", self.write_to_mmap_us, i64),
            ("create_save_us", self.create_save_us, i64),
            ("load_us", self.load_us, i64),
            ("read_us", self.read_us, i64),
            ("decode_us", self.decode_us, i64),
            ("unused_cache_files", self.unused_cache_files, i64),
        );
    }
}
