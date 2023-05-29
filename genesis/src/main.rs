//! A command-line executable for generating the chain's genesis config.用于生成链的genesis配置的命令行可执行文件
#![allow(clippy::integer_arithmetic)]

use {
    clap::{crate_description, crate_name, value_t, value_t_or_exit, App, Arg, ArgMatches},
    evm_state::U256,
    log::{error, info},
    clap_utils::{
        input_parsers::{
            cluster_type_of, pubkey_of, pubkeys_of, unix_timestamp_from_rfc3339_datetime,
        },
        input_validators::{
            is_pubkey_or_keypair, is_rfc3339_datetime, is_slot, is_valid_percentage,
        },
    },
    entry::poh::compute_hashes_per_tick,
    genesis::Base64Account,
    ledger::{blockstore_db::AccessType},//blockstore::create_new_ledger,
    runtime::hardened_unpack::MAX_GENESIS_ARCHIVE_UNPACKED_SIZE,//定义了创世档案文件解压后的最大大小。700MB
    sdk::{
        account::{Account, AccountSharedData, ReadableAccount, WritableAccount},
        clock,
        epoch_schedule::EpochSchedule,
        fee_calculator::FeeRateGovernor,
        genesis_config::{self, ClusterType, GenesisConfig},
        inflation::Inflation,
        native_token::sol_to_lamports,
        poh_config::PohConfig,
        pubkey::Pubkey,
        rent::Rent,
        signature::{Keypair, Signer},
        stake::state::StakeState,
        system_program, timing,
    },
    //stake_program::stake_state,//内容过多，暂不解析
    vote_program::vote_state::{self, VoteState},
    std::{
        collections::HashMap,
        error,
        fs::File,
        io::{self, Read},
        path::PathBuf,
        process,
        str::FromStr,
        time::Duration,
    },
};
pub enum AccountFileFormat {//账户文件
    Pubkey,
    Keypair,
}
fn pubkey_from_str(key_str: &str) -> Result<Pubkey, Box<dyn error::Error>> {
    Pubkey::from_str(key_str).or_else(|_| {
        let bytes: Vec<u8> = serde_json::from_str(key_str)?;
        let keypair = Keypair::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(keypair.pubkey())
    })
}
pub fn load_genesis_accounts(file: &str, genesis_config: &mut GenesisConfig) -> io::Result<u64> {
    let mut lamports = 0;
    let accounts_file = File::open(file)?;

    let genesis_accounts: HashMap<String, Base64Account> =
        serde_yaml::from_reader(accounts_file)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, format!("{:?}", err)))?;

    for (key, account_details) in genesis_accounts {
        let pubkey = pubkey_from_str(key.as_str()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid pubkey/keypair {}: {:?}", key, err),
            )
        })?;

        let owner_program_id = Pubkey::from_str(account_details.owner.as_str()).map_err(|err| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid owner: {}: {:?}", account_details.owner, err),
            )
        })?;

        let mut account = AccountSharedData::new(account_details.balance, 0, &owner_program_id);
        if account_details.data != "~" {
            account.set_data(
                base64::decode(account_details.data.as_str()).map_err(|err| {
                    io::Error::new(
                        io::ErrorKind::Other,
                        format!("Invalid account data: {}: {:?}", account_details.data, err),
                    )
                })?,
            );
        }
        account.set_executable(account_details.executable);
        lamports += account.lamports();
        genesis_config.add_account(pubkey, account);
    }

    Ok(lamports)
}
#[allow(clippy::cognitive_complexity)]
fn main() -> Result<(), Box<dyn error::Error>> {
let default_faucet_pubkey = cli_config::Config::default().keypair_path;
    let fee_rate_governor = FeeRateGovernor::default();
    let (
        default_target_lamports_per_signature,
        default_target_signatures_per_slot,
        default_fee_burn_percentage,
    ) = {
        (
            &fee_rate_governor.target_lamports_per_signature.to_string(),
            &fee_rate_governor.target_signatures_per_slot.to_string(),
            &fee_rate_governor.burn_percent.to_string(),
        )
    };

    let rent = Rent::default();
    let (
        default_lamports_per_byte_year,
        default_rent_exemption_threshold,
        default_rent_burn_percentage,
    ) = {
        (
            &rent.lamports_per_byte_year.to_string(),
            &rent.exemption_threshold.to_string(),
            &rent.burn_percent.to_string(),
        )
    };

    // vote account 投票账户
    let default_bootstrap_validator_lamports = &sol_to_lamports(500.0)
        .max(VoteState::get_rent_exempt_reserve(&rent))
        .to_string();
    // stake account 质押账户
    let default_bootstrap_validator_stake_lamports = &sol_to_lamports(0.5)
        .max(StakeState::get_rent_exempt_reserve(&rent)).to_string();

    let default_target_tick_duration =
        timing::duration_as_us(&PohConfig::default().target_tick_duration);
    let default_ticks_per_slot = &clock::DEFAULT_TICKS_PER_SLOT.to_string();
    let default_cluster_type = "mainnet-beta";
    let default_genesis_archive_unpacked_size = MAX_GENESIS_ARCHIVE_UNPACKED_SIZE.to_string();
    let version = version::version!();
    let app = App::new(crate_name!())
        .about(crate_description!())
        .version(version)
        .arg(
            Arg::with_name("creation_time")
                .long("creation-time")
                .value_name("RFC3339 DATE TIME")
                .validator(is_rfc3339_datetime)
                .takes_value(true)
                .help("Time when the bootstrap validator will start the cluster [default: current system time]"),
        )
        // .arg(
        //     Arg::with_name("bootstrap_validator")// 定义第二个参数bootstrap_validator。
        //         .short("b")//它的短选项为"b"
        //         .long("bootstrap-validator")//长选项为"bootstrap-validator"。
        //         .value_name("IDENTITY_PUBKEY VOTE_PUBKEY STAKE_PUBKEY")//要求三个pubkey或keypair的值
        //         .takes_value(true)
        //         .validator(is_pubkey_or_keypair)//使用is_pubkey_or_keypair验证器验证。
        //         .number_of_values(3)//参数接受的值数量、
        //         .multiple(true)//是否允许多次输入
        //         .required(true)//是否为必填
        //         .help("The bootstrap validator's identity, vote and stake pubkeys"),
        // )
        // .arg(
        //     Arg::with_name("ledger_path")
        //         .short("l")
        //         .long("ledger")
        //         .value_name("DIR")
        //         .takes_value(true)//需要指定值
        //         .required(true)//必填
        //         .help("Use directory as persistent ledger location"),//使用目录作为持久化账本位置
        // )
        .arg(
            Arg::with_name("faucet_lamports")
                .short("t")
                .long("faucet-lamports")
                .value_name("LAMPORTS")
                .takes_value(true)
                .help("Number of lamports to assign to the faucet"),
    )
        // .arg(
        //     Arg::with_name("faucet_pubkey")//参数的名称为"faucet_pubkey"。
        //         .short("m")//短选项"-m"
        //         .long("faucet-pubkey")//长选项"--faucet-pubkey"。
        //         .value_name("PUBKEY")//值的名称为"PUBKEY",且要求一个值
        //         .takes_value(true)
        //         .validator(is_pubkey_or_keypair)//使用is_pubkey_or_keypair验证器验证输入的值。
        //         .requires("faucet_lamports")//参数需要同时指定"faucet_lamports"参数，使用requires方法指定这个依赖关系。//该参数依赖于faucet_lamports
        //         .default_value(&default_faucet_pubkey)//使用default_value方法为该参数指定一个默认值default_faucet_pubkey。
        //         .help("Path to file containing the faucet's pubkey"),
        // )
        .arg(
            Arg::with_name("bootstrap_stake_authorized_pubkey")
                .long("bootstrap-stake-authorized-pubkey")
                .value_name("BOOTSTRAP STAKE AUTHORIZED PUBKEY")
                .takes_value(true)
                .validator(is_pubkey_or_keypair)
                .help(
                    "Path to file containing the pubkey authorized to manage the bootstrap \
                     validator's stake [default: --bootstrap-validator IDENTITY_PUBKEY]",
                ),
        )
        .arg(
            Arg::with_name("bootstrap_validator_lamports")
                .long("bootstrap-validator-lamports")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_bootstrap_validator_lamports)
                .help("Number of lamports to assign to the bootstrap validator"),
        )
        .arg(
            Arg::with_name("bootstrap_validator_stake_lamports")
                .long("bootstrap-validator-stake-lamports")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_bootstrap_validator_stake_lamports)
                .help("Number of lamports to assign to the bootstrap validator's stake account"),
        )
        .arg(
            Arg::with_name("target_lamports_per_signature")
                .long("target-lamports-per-signature")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_target_lamports_per_signature)
                .help(
                    "The cost in lamports that the cluster will charge for signature \
                     verification when the cluster is operating at target-signatures-per-slot",
                ),
        )
        .arg(
            Arg::with_name("lamports_per_byte_year")
                .long("lamports-per-byte-year")
                .value_name("LAMPORTS")
                .takes_value(true)
                .default_value(default_lamports_per_byte_year)
                .help(
                    "The cost in lamports that the cluster will charge per byte per year \
                     for accounts with data",
                ), 
        )
        .arg(
            Arg::with_name("rent_exemption_threshold")
                .long("rent-exemption-threshold")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_rent_exemption_threshold)
                .help(
                    "amount of time (in years) the balance has to include rent for \
                     to qualify as rent exempted account",
                ),
        )
        .arg(
            Arg::with_name("rent_burn_percentage")
                .long("rent-burn-percentage")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_rent_burn_percentage)
                .help("percentage of collected rent to burn")
                .validator(is_valid_percentage),
        )
        .arg(
            Arg::with_name("fee_burn_percentage")
                .long("fee-burn-percentage")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_fee_burn_percentage)
                .help("percentage of collected fee to burn")
                .validator(is_valid_percentage),
        )
        .arg(
            Arg::with_name("vote_commission_percentage")
                .long("vote-commission-percentage")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value("100")
                .help("percentage of vote commission")
                .validator(is_valid_percentage),
        )
        .arg(
            Arg::with_name("target_signatures_per_slot")
                .long("target-signatures-per-slot")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(default_target_signatures_per_slot)
                .help(
                    "Used to estimate the desired processing capacity of the cluster. \
                    When the latest slot processes fewer/greater signatures than this \
                    value, the lamports-per-signature fee will decrease/increase for \
                    the next slot. A value of 0 disables signature-based fee adjustments",
                ),
        )
        .arg(
            Arg::with_name("target_tick_duration")
                .long("target-tick-duration")
                .value_name("MILLIS")
                .takes_value(true)
                .help("The target tick rate of the cluster in milliseconds"),
        )
       

        .arg(
            Arg::with_name("hashes_per_tick")
                .long("hashes-per-tick")
                .value_name("NUM_HASHES|\"auto\"|\"sleep\"")
                .takes_value(true)
                .default_value("auto")
                .help(
                    "How many PoH hashes to roll before emitting the next tick. \
                     If \"auto\", determine based on --target-tick-duration \
                     and the hash rate of this computer. If \"sleep\", for development \
                     sleep for --target-tick-duration instead of hashing",
                ),
        )
        .arg(
            Arg::with_name("ticks_per_slot")
                .long("ticks-per-slot")
                .value_name("TICKS")
                .takes_value(true)
                .default_value(default_ticks_per_slot)
                .help("The number of ticks in a slot"),
        )
      
        .arg(
            Arg::with_name("slots_per_epoch")
                .long("slots-per-epoch")
                .value_name("SLOTS")
                .validator(is_slot)
                .takes_value(true)
                .help("The number of slots in an epoch"),
        )
        
        .arg(
            Arg::with_name("enable_warmup_epochs")
                .long("enable-warmup-epochs")
                .help(
                    "When enabled epochs start short and will grow. \
                     Useful for warming up stake quickly during development"
                ),
        )
        .arg(
            Arg::with_name("primordial_accounts_file")
                .long("primordial-accounts-file")
                .value_name("FILENAME")
                .takes_value(true)
                .multiple(true)
                .help("The location of pubkey for primordial accounts and balance"),
                
        )
        .arg(
            Arg::with_name("cluster_type")  
                .long("cluster-type")
                .possible_values(&ClusterType::STRINGS)
                .takes_value(true)
                .default_value(default_cluster_type)
                .help(
                    "Selects the features that will be enabled for the cluster"
                ),
        )
        .arg(
            Arg::with_name("max_genesis_archive_unpacked_size")
                .long("max-genesis-archive-unpacked-size")
                .value_name("NUMBER")
                .takes_value(true)
                .default_value(&default_genesis_archive_unpacked_size)
                .help(
                    "maximum total uncompressed file size of created genesis archive",
                ),
        )
        .arg(
            Arg::with_name("bpf_program")
                .long("bpf-program")
                .value_name("ADDRESS BPF_PROGRAM.SO")
                .takes_value(true)
                .number_of_values(3)
                .multiple(true)
                .help("Install a BPF program at the given address"),
        )
        
        .arg(
            Arg::with_name("inflation")
                .required(false)
                .long("inflation")
                .takes_value(true)
                .possible_values(&["pico", "full", "none"])
                .help("Selects inflation"),
        );
        
    let matches = if cfg!(feature = "with_evm") {
        app.arg(
            Arg::with_name("evm-root")
                .long("evm-root")
                .takes_value(true)
                .help("Root hash for evm state snapshot, Used to verify snapshot integrity."),
        ).arg(
            Arg::with_name("evm-state-file")
                .long("evm-state-file")
                .takes_value(true)
                .help("Path to EVM state json file, can be retrived from `parity export state` command."),
        ).arg(
            Arg::with_name("evm-chain-id")
                .required(false)
                .long("evm-chain-id")
                .takes_value(true)
                .help("EVM chain id"),
        )

    } else {
        app
    }
    .get_matches();

     Ok(())
}