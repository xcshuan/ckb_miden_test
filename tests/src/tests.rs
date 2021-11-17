use std::io::Write;
use std::time::Instant;

use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

use log::debug;
use miden::{ProofOptions, StarkProof};
use miden_examples::Example;

const MAX_CYCLES: u64 = 10_000_000;
const MIDEN_PROGRAM: &str = "MIDEN_PROGRAME";
const MIDEN_VALUE: &str = "MIDEN_VALUE";
const SERCURITY_LEVEL : &str = "SERCURITY_LEVEL";

#[test]
fn test_miden_cycles() {
    // configure logging
    env_logger::Builder::new()
        .format(|buf, record| writeln!(buf, "{}", record.args()))
        .filter_level(log::LevelFilter::Debug)
        .init();

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("miden_test");
    let out_point = context.deploy_cell(contract_bin);

    println!("begin");

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(vec![42]))
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // instantiate and prepare the example
    let example = match env::var(MIDEN_PROGRAM) {
        Ok(val) => {
            let value = match env::var(MIDEN_VALUE) {
                Ok(val) => val.parse::<usize>(),
                Err(_) => Ok(0),
            };

            match val.as_str() {
                "fib" => miden_examples::fibonacci::get_example(value.unwrap_or(1024)),
                "merkle" => miden_examples::merkle::get_example(value.unwrap_or(20)),
                "collatz" => miden_examples::collatz::get_example(value.unwrap_or(511)),
                "comparison" => miden_examples::comparison::get_example(value.unwrap_or(11)),
                "conditional" => miden_examples::conditional::get_example(value.unwrap_or(1)),
                "range" => miden_examples::range::get_example(value.unwrap_or(100)),
                _ => miden_examples::fibonacci::get_example(value.unwrap_or(1024)),
            }
        }
        Err(_) => miden_examples::fibonacci::get_example(1024),
    };

    debug!("============================================================");

    let proof_options = match env::var(SERCURITY_LEVEL) {
        Ok(val) => match val.as_str() {
            "128" => ProofOptions::with_128_bit_security(),
            _ => ProofOptions::with_96_bit_security(),
        },
        Err(_) => ProofOptions::with_96_bit_security(),
    };

    let Example {
        program,
        inputs,
        num_outputs,
        pub_inputs,
        expected_result,
    } = example;

    debug!("--------------------------------");

    // execute the program and generate the proof of execution

    let now = Instant::now();
    let (stark_outputs, proof) =
        miden::execute(&program, &inputs, num_outputs, &proof_options).unwrap();
    debug!("--------------------------------");

    debug!(
        "Executed program with hash {} in {} ms",
        hex::encode(program.hash()),
        now.elapsed().as_millis()
    );
    debug!("Program output: {:?}", stark_outputs);
    assert_eq!(
        expected_result, stark_outputs,
        "Program result was computed incorrectly"
    );

    // serialize the proof to see how big it is
    let proof_bytes = proof.to_bytes();
    debug!("Execution proof size: {} KB", proof_bytes.len() / 1024);

    debug!(
        "Execution proof security: {} bits",
        proof.security_level(true)
    );
    debug!("--------------------------------");

    // verify that executing a program with a given hash and given inputs
    // results in the expected output
    let proof = StarkProof::from_bytes(&proof_bytes).unwrap();
    let now = Instant::now();
    match miden::verify(*program.hash(), &pub_inputs, &stark_outputs, proof) {
        Ok(_) => debug!("Execution verified in {} ms", now.elapsed().as_millis()),
        Err(msg) => debug!("Failed to verify execution: {}", msg),
    }

    let cell_data = Bytes::copy_from_slice(&*program.hash());
    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        cell_data.clone(),
    );

    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![CellOutput::new_builder()
        .capacity(1000u64.pack())
        .lock(lock_script.clone())
        .build()];

    let outputs_data = vec![cell_data];

    let pub_inputs_flatten: Vec<u8> = pub_inputs
        .iter()
        .map(|x| x.to_ne_bytes())
        .flatten()
        .collect();
    let outputs_flatten: Vec<u8> = stark_outputs
        .iter()
        .map(|x| x.to_ne_bytes())
        .flatten()
        .collect();

    let witness = WitnessArgsBuilder::default()
        .input_type(Some(Bytes::copy_from_slice(&pub_inputs_flatten)).pack())
        .output_type(Some(Bytes::copy_from_slice(&outputs_flatten)).pack())
        .lock(Some(Bytes::copy_from_slice(&proof_bytes)).pack())
        .build();

    debug!("Witness len: {} byte", witness.as_bytes().len());

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .witness(witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
