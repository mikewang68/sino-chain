use {
    byteorder::{ByteOrder, LittleEndian, WriteBytesExt},
    solana_rbpf::{aligned_memory::AlignedMemory, ebpf::HOST_ALIGN},
    sdk::{
        account::{ReadableAccount, WritableAccount},
        bpf_loader_deprecated,
        entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE},
        instruction::InstructionError,
        keyed_account::KeyedAccount,
        pubkey::Pubkey,
        system_instruction::MAX_PERMITTED_DATA_LENGTH,
    },
    std::{io::prelude::*, mem::size_of},
};

/// Look for a duplicate account and return its position if found
pub fn is_dup(accounts: &[KeyedAccount], keyed_account: &KeyedAccount) -> (bool, usize) {
    for (i, account) in accounts.iter().enumerate() {
        if account == keyed_account {
            return (true, i);
        }
    }
    (false, 0)
}

pub fn serialize_parameters(
    loader_id: &Pubkey,
    program_id: &Pubkey,
    keyed_accounts: &[KeyedAccount],
    data: &[u8],
) -> Result<(AlignedMemory, Vec<usize>), InstructionError> {
    if *loader_id == bpf_loader_deprecated::id() {
        serialize_parameters_unaligned(program_id, keyed_accounts, data)
    } else {
        serialize_parameters_aligned(program_id, keyed_accounts, data)
    }
    .and_then(|buffer| {
        let account_lengths = keyed_accounts
            .iter()
            .map(|keyed_account| keyed_account.data_len())
            .collect::<Result<Vec<usize>, InstructionError>>()?;
        Ok((buffer, account_lengths))
    })
}

pub fn deserialize_parameters(
    loader_id: &Pubkey,
    keyed_accounts: &[KeyedAccount],
    buffer: &[u8],
    account_lengths: &[usize],
    do_support_realloc: bool,
) -> Result<(), InstructionError> {
    if *loader_id == bpf_loader_deprecated::id() {
        deserialize_parameters_unaligned(keyed_accounts, buffer, account_lengths)
    } else {
        deserialize_parameters_aligned(keyed_accounts, buffer, account_lengths, do_support_realloc)
    }
}

pub fn get_serialized_account_size_unaligned(
    keyed_account: &KeyedAccount,
) -> Result<usize, InstructionError> {
    let data_len = keyed_account.data_len()?;
    Ok(
        size_of::<u8>() // is_signer
            + size_of::<u8>() // is_writable
            + size_of::<Pubkey>() // key
            + size_of::<u64>()  // wens
            + size_of::<u64>()  // data len
            + data_len // data
            + size_of::<Pubkey>() // owner
            + size_of::<u8>() // executable
            + size_of::<u64>(), // rent_epoch
    )
}

pub fn serialize_parameters_unaligned(
    program_id: &Pubkey,
    keyed_accounts: &[KeyedAccount],
    instruction_data: &[u8],
) -> Result<AlignedMemory, InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for (i, keyed_account) in keyed_accounts.iter().enumerate() {
        let (is_dup, _) = is_dup(&keyed_accounts[..i], keyed_account);
        size += 1; // dup
        if !is_dup {
            size += get_serialized_account_size_unaligned(keyed_account)?;
        }
    }
    size += size_of::<u64>() // instruction data len
         + instruction_data.len() // instruction data
         + size_of::<Pubkey>(); // program id
    let mut v = AlignedMemory::new(size, HOST_ALIGN);

    v.write_u64::<LittleEndian>(keyed_accounts.len() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    for (i, keyed_account) in keyed_accounts.iter().enumerate() {
        let (is_dup, position) = is_dup(&keyed_accounts[..i], keyed_account);
        if is_dup {
            v.write_u8(position as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
        } else {
            v.write_u8(std::u8::MAX)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(keyed_account.signer_key().is_some() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(keyed_account.is_writable() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(keyed_account.unsigned_key().as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(keyed_account.wens()?)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(keyed_account.data_len()? as u64)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(keyed_account.try_account_ref()?.data())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(keyed_account.owner()?.as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(keyed_account.executable()? as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(keyed_account.rent_epoch()?)
                .map_err(|_| InstructionError::InvalidArgument)?;
        }
    }
    v.write_u64::<LittleEndian>(instruction_data.len() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(instruction_data)
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(program_id.as_ref())
        .map_err(|_| InstructionError::InvalidArgument)?;
    Ok(v)
}

pub fn deserialize_parameters_unaligned(
    keyed_accounts: &[KeyedAccount],
    buffer: &[u8],
    account_lengths: &[usize],
) -> Result<(), InstructionError> {
    let mut start = size_of::<u64>(); // number of accounts
    for (i, (keyed_account, _pre_len)) in keyed_accounts
        .iter()
        .zip(account_lengths.iter())
        .enumerate()
    {
        let (is_dup, _) = is_dup(&keyed_accounts[..i], keyed_account);
        start += 1; // is_dup
        if !is_dup {
            start += size_of::<u8>(); // is_signer
            start += size_of::<u8>(); // is_writable
            start += size_of::<Pubkey>(); // key
            keyed_account
                .try_account_ref_mut()?
                .set_wens(LittleEndian::read_u64(&buffer[start..]));
            start += size_of::<u64>() // wens
                + size_of::<u64>(); // data length
            let end = start + keyed_account.data_len()?;
            keyed_account
                .try_account_ref_mut()?
                .set_data_from_slice(&buffer[start..end]);
            start += keyed_account.data_len()? // data
                + size_of::<Pubkey>() // owner
                + size_of::<u8>() // executable
                + size_of::<u64>(); // rent_epoch
        }
    }
    Ok(())
}

pub fn get_serialized_account_size_aligned(
    keyed_account: &KeyedAccount,
) -> Result<usize, InstructionError> {
    let data_len = keyed_account.data_len()?;
    Ok(
        size_of::<u8>() // is_signer
            + size_of::<u8>() // is_writable
            + size_of::<u8>() // executable
            + 4 // padding to 128-bit aligned
            + size_of::<Pubkey>()  // key
            + size_of::<Pubkey>() // owner
            + size_of::<u64>()  // wens
            + size_of::<u64>()  // data len
            + data_len
            + MAX_PERMITTED_DATA_INCREASE
            + (data_len as *const u8).align_offset(BPF_ALIGN_OF_U128)
            + size_of::<u64>(), // rent epoch
    )
}

pub fn serialize_parameters_aligned(
    program_id: &Pubkey,
    keyed_accounts: &[KeyedAccount],
    instruction_data: &[u8],
) -> Result<AlignedMemory, InstructionError> {
    // Calculate size in order to alloc once
    let mut size = size_of::<u64>();
    for (i, keyed_account) in keyed_accounts.iter().enumerate() {
        let (is_dup, _) = is_dup(&keyed_accounts[..i], keyed_account);
        size += 1; // dup
        if is_dup {
            size += 7; // padding to 64-bit aligned
        } else {
            size += get_serialized_account_size_aligned(keyed_account)?;
        }
    }
    size += size_of::<u64>() // data len
    + instruction_data.len()
    + size_of::<Pubkey>(); // program id;
    let mut v = AlignedMemory::new(size, HOST_ALIGN);

    // Serialize into the buffer
    v.write_u64::<LittleEndian>(keyed_accounts.len() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    for (i, keyed_account) in keyed_accounts.iter().enumerate() {
        let (is_dup, position) = is_dup(&keyed_accounts[..i], keyed_account);
        if is_dup {
            v.write_u8(position as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(&[0u8, 0, 0, 0, 0, 0, 0])
                .map_err(|_| InstructionError::InvalidArgument)?; // 7 bytes of padding to make 64-bit aligned
        } else {
            v.write_u8(std::u8::MAX)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(keyed_account.signer_key().is_some() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(keyed_account.is_writable() as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u8(keyed_account.executable()? as u8)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(&[0u8, 0, 0, 0])
                .map_err(|_| InstructionError::InvalidArgument)?; // 4 bytes of padding to make 128-bit aligned
            v.write_all(keyed_account.unsigned_key().as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(keyed_account.owner()?.as_ref())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(keyed_account.wens()?)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(keyed_account.data_len()? as u64)
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_all(keyed_account.try_account_ref()?.data())
                .map_err(|_| InstructionError::InvalidArgument)?;
            v.resize(
                MAX_PERMITTED_DATA_INCREASE
                    + (v.write_index() as *const u8).align_offset(BPF_ALIGN_OF_U128),
                0,
            )
            .map_err(|_| InstructionError::InvalidArgument)?;
            v.write_u64::<LittleEndian>(keyed_account.rent_epoch()?)
                .map_err(|_| InstructionError::InvalidArgument)?;
        }
    }
    v.write_u64::<LittleEndian>(instruction_data.len() as u64)
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(instruction_data)
        .map_err(|_| InstructionError::InvalidArgument)?;
    v.write_all(program_id.as_ref())
        .map_err(|_| InstructionError::InvalidArgument)?;
    Ok(v)
}

pub fn deserialize_parameters_aligned(
    keyed_accounts: &[KeyedAccount],
    buffer: &[u8],
    account_lengths: &[usize],
    do_support_realloc: bool,
) -> Result<(), InstructionError> {
    let mut start = size_of::<u64>(); // number of accounts
    for (i, (keyed_account, pre_len)) in keyed_accounts
        .iter()
        .zip(account_lengths.iter())
        .enumerate()
    {
        let (is_dup, _) = is_dup(&keyed_accounts[..i], keyed_account);
        start += size_of::<u8>(); // position
        if is_dup {
            start += 7; // padding to 64-bit aligned
        } else {
            let mut account = keyed_account.try_account_ref_mut()?;
            start += size_of::<u8>() // is_signer
                + size_of::<u8>() // is_writable
                + size_of::<u8>() // executable
                + 4 // padding to 128-bit aligned
                + size_of::<Pubkey>(); // key
            account.copy_into_owner_from_slice(&buffer[start..start + size_of::<Pubkey>()]);
            start += size_of::<Pubkey>(); // owner
            account.set_wens(LittleEndian::read_u64(&buffer[start..]));
            start += size_of::<u64>(); // wens
            let post_len = LittleEndian::read_u64(&buffer[start..]) as usize;
            start += size_of::<u64>(); // data length
            let data_end = if do_support_realloc {
                if post_len.saturating_sub(*pre_len) > MAX_PERMITTED_DATA_INCREASE
                    || post_len > MAX_PERMITTED_DATA_LENGTH as usize
                {
                    return Err(InstructionError::InvalidRealloc);
                }
                start + post_len
            } else {
                let mut data_end = start + *pre_len;
                if post_len != *pre_len
                    && (post_len.saturating_sub(*pre_len)) <= MAX_PERMITTED_DATA_INCREASE
                {
                    data_end = start + post_len;
                }
                data_end
            };
            account.set_data_from_slice(&buffer[start..data_end]);
            start += *pre_len + MAX_PERMITTED_DATA_INCREASE; // data
            start += (start as *const u8).align_offset(BPF_ALIGN_OF_U128);
            start += size_of::<u64>(); // rent_epoch
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use {
        super::*,
        program_runtime::invoke_context::{prepare_mock_invoke_context, InvokeContext},
        sdk::{
            account::{Account, AccountSharedData},
            account_info::AccountInfo,
            bpf_loader,
            entrypoint::deserialize,
        },
        std::{
            cell::RefCell,
            rc::Rc,
            slice::{from_raw_parts, from_raw_parts_mut},
        },
    };

    #[test]
    fn test_serialize_parameters() {
        let program_id = sdk::pubkey::new_rand();
        let dup_key = sdk::pubkey::new_rand();
        let dup_key2 = sdk::pubkey::new_rand();
        let keyed_accounts = [
            (
                false,
                false,
                program_id,
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 0,
                    data: vec![],
                    owner: bpf_loader::id(),
                    executable: true,
                    rent_epoch: 0,
                }))),
            ),
            (
                false,
                false,
                dup_key,
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 1,
                    data: vec![1u8, 2, 3, 4, 5],
                    owner: bpf_loader::id(),
                    executable: false,
                    rent_epoch: 100,
                }))),
            ),
            (
                false,
                false,
                dup_key,
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 1,
                    data: vec![1u8, 2, 3, 4, 5],
                    owner: bpf_loader::id(),
                    executable: false,
                    rent_epoch: 100,
                }))),
            ),
            (
                false,
                false,
                sdk::pubkey::new_rand(),
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 2,
                    data: vec![11u8, 12, 13, 14, 15, 16, 17, 18, 19],
                    owner: bpf_loader::id(),
                    executable: true,
                    rent_epoch: 200,
                }))),
            ),
            (
                false,
                false,
                sdk::pubkey::new_rand(),
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 3,
                    data: vec![],
                    owner: bpf_loader::id(),
                    executable: false,
                    rent_epoch: 3100,
                }))),
            ),
            (
                false,
                true,
                dup_key2,
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 4,
                    data: vec![1u8, 2, 3, 4, 5],
                    owner: bpf_loader::id(),
                    executable: false,
                    rent_epoch: 100,
                }))),
            ),
            (
                false,
                true,
                dup_key2,
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 4,
                    data: vec![1u8, 2, 3, 4, 5],
                    owner: bpf_loader::id(),
                    executable: false,
                    rent_epoch: 100,
                }))),
            ),
            (
                false,
                true,
                sdk::pubkey::new_rand(),
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 5,
                    data: vec![11u8, 12, 13, 14, 15, 16, 17, 18, 19],
                    owner: bpf_loader::id(),
                    executable: true,
                    rent_epoch: 200,
                }))),
            ),
            (
                false,
                true,
                sdk::pubkey::new_rand(),
                Rc::new(RefCell::new(AccountSharedData::from(Account {
                    wens: 6,
                    data: vec![],
                    owner: bpf_loader::id(),
                    executable: false,
                    rent_epoch: 3100,
                }))),
            ),
        ];
        let instruction_data = vec![1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let program_indices = [0];
        let preparation =
            prepare_mock_invoke_context(&program_indices, &instruction_data, &keyed_accounts);
        let mut invoke_context = InvokeContext::new_mock(&preparation.accounts, &[]);
        invoke_context
            .push(
                &preparation.message,
                &preparation.message.instructions()[0],
                &program_indices,
                &preparation.account_indices,
            )
            .unwrap();

        // check serialize_parameters_aligned

        let ser_keyed_accounts = invoke_context.get_keyed_accounts().unwrap();
        let (mut serialized, account_lengths) = serialize_parameters(
            &bpf_loader::id(),
            &program_id,
            &ser_keyed_accounts[1..],
            &instruction_data,
        )
        .unwrap();

        let (de_program_id, de_accounts, de_instruction_data) =
            unsafe { deserialize(&mut serialized.as_slice_mut()[0] as *mut u8) };

        assert_eq!(&program_id, de_program_id);
        assert_eq!(instruction_data, de_instruction_data);
        assert_eq!(
            (&de_instruction_data[0] as *const u8).align_offset(BPF_ALIGN_OF_U128),
            0
        );
        for ((_, _, key, account), account_info) in keyed_accounts.iter().skip(1).zip(de_accounts) {
            assert_eq!(key, account_info.key);
            let account = account.borrow();
            assert_eq!(account.wens(), account_info.wens());
            assert_eq!(account.data(), &account_info.data.borrow()[..]);
            assert_eq!(account.owner(), account_info.owner);
            assert_eq!(account.executable(), account_info.executable);
            assert_eq!(account.rent_epoch(), account_info.rent_epoch);

            assert_eq!(
                (*account_info.wens.borrow() as *const u64).align_offset(BPF_ALIGN_OF_U128),
                0
            );
            assert_eq!(
                account_info
                    .data
                    .borrow()
                    .as_ptr()
                    .align_offset(BPF_ALIGN_OF_U128),
                0
            );
        }

        let de_keyed_accounts = invoke_context.get_keyed_accounts().unwrap();
        deserialize_parameters(
            &bpf_loader::id(),
            &de_keyed_accounts[1..],
            serialized.as_slice(),
            &account_lengths,
            true,
        )
        .unwrap();
        for ((_, _, key, account), de_keyed_account) in keyed_accounts.iter().zip(de_keyed_accounts)
        {
            assert_eq!(key, de_keyed_account.unsigned_key());
            let account = account.borrow();
            assert_eq!(account.executable(), de_keyed_account.executable().unwrap());
            assert_eq!(account.rent_epoch(), de_keyed_account.rent_epoch().unwrap());
        }

        // check serialize_parameters_unaligned

        let ser_keyed_accounts = invoke_context.get_keyed_accounts().unwrap();
        let (mut serialized, account_lengths) = serialize_parameters(
            &bpf_loader_deprecated::id(),
            &program_id,
            &ser_keyed_accounts[1..],
            &instruction_data,
        )
        .unwrap();

        let (de_program_id, de_accounts, de_instruction_data) =
            unsafe { deserialize_unaligned(&mut serialized.as_slice_mut()[0] as *mut u8) };
        assert_eq!(&program_id, de_program_id);
        assert_eq!(instruction_data, de_instruction_data);
        for ((_, _, key, account), account_info) in keyed_accounts.iter().skip(1).zip(de_accounts) {
            assert_eq!(key, account_info.key);
            let account = account.borrow();
            assert_eq!(account.wens(), account_info.wens());
            assert_eq!(account.data(), &account_info.data.borrow()[..]);
            assert_eq!(account.owner(), account_info.owner);
            assert_eq!(account.executable(), account_info.executable);
            assert_eq!(account.rent_epoch(), account_info.rent_epoch);
        }

        let de_keyed_accounts = invoke_context.get_keyed_accounts().unwrap();
        deserialize_parameters(
            &bpf_loader_deprecated::id(),
            &de_keyed_accounts[1..],
            serialized.as_slice(),
            &account_lengths,
            true,
        )
        .unwrap();
        for ((_, _, key, account), de_keyed_account) in keyed_accounts.iter().zip(de_keyed_accounts)
        {
            assert_eq!(key, de_keyed_account.unsigned_key());
            let account = account.borrow();
            assert_eq!(account.wens(), de_keyed_account.wens().unwrap());
            assert_eq!(
                account.data(),
                de_keyed_account.try_account_ref().unwrap().data()
            );
            assert_eq!(*account.owner(), de_keyed_account.owner().unwrap());
            assert_eq!(account.executable(), de_keyed_account.executable().unwrap());
            assert_eq!(account.rent_epoch(), de_keyed_account.rent_epoch().unwrap());
        }
    }

    // the old bpf_loader in-program deserializer bpf_loader::id()
    #[allow(clippy::type_complexity)]
    pub unsafe fn deserialize_unaligned<'a>(
        input: *mut u8,
    ) -> (&'a Pubkey, Vec<AccountInfo<'a>>, &'a [u8]) {
        let mut offset: usize = 0;

        // number of accounts present

        #[allow(clippy::cast_ptr_alignment)]
        let num_accounts = *(input.add(offset) as *const u64) as usize;
        offset += size_of::<u64>();

        // account Infos

        let mut accounts = Vec::with_capacity(num_accounts);
        for _ in 0..num_accounts {
            let dup_info = *(input.add(offset) as *const u8);
            offset += size_of::<u8>();
            if dup_info == std::u8::MAX {
                #[allow(clippy::cast_ptr_alignment)]
                let is_signer = *(input.add(offset) as *const u8) != 0;
                offset += size_of::<u8>();

                #[allow(clippy::cast_ptr_alignment)]
                let is_writable = *(input.add(offset) as *const u8) != 0;
                offset += size_of::<u8>();

                let key: &Pubkey = &*(input.add(offset) as *const Pubkey);
                offset += size_of::<Pubkey>();

                #[allow(clippy::cast_ptr_alignment)]
                let wens = Rc::new(RefCell::new(&mut *(input.add(offset) as *mut u64)));
                offset += size_of::<u64>();

                #[allow(clippy::cast_ptr_alignment)]
                let data_len = *(input.add(offset) as *const u64) as usize;
                offset += size_of::<u64>();

                let data = Rc::new(RefCell::new({
                    from_raw_parts_mut(input.add(offset), data_len)
                }));
                offset += data_len;

                let owner: &Pubkey = &*(input.add(offset) as *const Pubkey);
                offset += size_of::<Pubkey>();

                #[allow(clippy::cast_ptr_alignment)]
                let executable = *(input.add(offset) as *const u8) != 0;
                offset += size_of::<u8>();

                #[allow(clippy::cast_ptr_alignment)]
                let rent_epoch = *(input.add(offset) as *const u64);
                offset += size_of::<u64>();

                accounts.push(AccountInfo {
                    key,
                    is_signer,
                    is_writable,
                    wens,
                    data,
                    owner,
                    executable,
                    rent_epoch,
                });
            } else {
                // duplicate account, clone the original
                accounts.push(accounts[dup_info as usize].clone());
            }
        }

        // instruction data

        #[allow(clippy::cast_ptr_alignment)]
        let instruction_data_len = *(input.add(offset) as *const u64) as usize;
        offset += size_of::<u64>();

        let instruction_data = { from_raw_parts(input.add(offset), instruction_data_len) };
        offset += instruction_data_len;

        // program Id

        let program_id: &Pubkey = &*(input.add(offset) as *const Pubkey);

        (program_id, accounts, instruction_data)
    }
}
