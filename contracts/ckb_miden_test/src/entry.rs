// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::Unpack,
    high_level::{load_cell_data, load_witness_args},
};

use miden_verifier::{verify, StarkProof};

use crate::error::Error;

fn convert_flatten_bytes(data: Vec<u8>) -> Vec<u128> {
    data.chunks(16)
        .map(|x| {
            let mut buf = [0u8; 16];
            buf.copy_from_slice(x);
            u128::from_le_bytes(buf)
        })
        .collect()
}


// 在cell_data放置代码的哈希，witness里放置输入、输出以及证明
pub fn main() -> Result<(), Error> {
    let mut program_hash = [0u8; 32];
    let program_hash_bytes = load_cell_data(0, Source::GroupInput).unwrap();
    program_hash.copy_from_slice(&program_hash_bytes);

    let witness = load_witness_args(0, Source::GroupInput).unwrap();
    let proof_bytes = if let Some(lock) = witness.lock().to_opt() {
        let res: Vec<u8> = lock.unpack();
        res
    } else {
        return Err(Error::ItemMissing);
    };
    let public_inputs_bytes = if let Some(input) = witness.input_type().to_opt() {
        let res: Vec<u8> = input.unpack();
        res
    } else {
        return Err(Error::ItemMissing);
    };
    let outputs_bytes = if let Some(output) = witness.output_type().to_opt() {
        let res: Vec<u8> = output.unpack();
        res
    } else {
        return Err(Error::ItemMissing);
    };

    let public_inputs = convert_flatten_bytes(public_inputs_bytes);
    let outputs = convert_flatten_bytes(outputs_bytes);
    let proof = StarkProof::from_bytes(&proof_bytes).unwrap();

    let res = verify(program_hash, &public_inputs, &outputs, proof);

    if res.is_err() {
        return Err(Error::MyError);
    }

    Ok(())
}
