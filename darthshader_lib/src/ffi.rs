use std::slice;
use libafl::mutators::MutatorsTuple;

use crate::{
    ast::mutate::ast_mutations,
    layeredinput::LayeredInput,
    mini_state::MiniState,
};

// IR mutations

use crate::ir::mutate::ir_mutations;

// use crate::ir::generator::IRGenerator;

// use crate::generator::IRGenerator;

//use crate::ast::mutate::ast_mutations;
// use crate::ir::mutate::ir_mutations;
use crate::generator::IRGenerator;

use libafl::generators::Generator;


// use crate::layeredinput::LayeredInput;
// use crate::mini_state::MiniState;


fn ast_to_ir(state: &mut MiniState) -> Option<LayeredInput> {
    let mut gen = IRGenerator::new(Default::default());
    match gen.generate(state) {
        Ok(LayeredInput::IR(ir)) => Some(LayeredInput::IR(ir)),
        _ => None,
    }
}

fn write_out(
    s: String,
    out_data: *mut *mut u8,
    out_size: *mut usize,
) -> i32 {
    let mut boxed = s.into_bytes().into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);

    unsafe {
        *out_data = ptr;
        *out_size = len;
    }
    0
}


#[no_mangle]
pub extern "C" fn darthshader_mutate(
    data: *const u8,
    size: usize,
    seed: u64,
    out_data: *mut *mut u8,
    out_size: *mut usize,
) -> i32 {
    if data.is_null() || out_data.is_null() || out_size.is_null() {
        return -1;
    }

    let input_bytes = unsafe { slice::from_raw_parts(data, size) };

    let mut input = match LayeredInput::from_wgsl_bytes(input_bytes) {
        Ok(v) => v,
        Err(_) => return -2,
    };

    let mut state = MiniState::new(seed);

    // Needed for ASTSpliceMutator to find another testcase
    state.add_input_to_corpus(input.clone());

    /*
    let mut muts = ast_mutations();
    let _ = muts.mutate_all(&mut state, &mut input, 0);

    let out = match input.to_wgsl_string() {
        Ok(s) => s.into_bytes(),
        Err(_) => return -3,
    };
    */

    // --------------------
    // Phase 1: AST
    // --------------------
    let mut ast_muts = ast_mutations();
    let _ = ast_muts.mutate_all(&mut state, &mut input, 0);

    // --------------------
    // Phase 2: AST → IR → IR mutations → WGSL
    // --------------------
    if matches!(input, LayeredInput::Ast(_)) {
        if let Some(mut ir_input) = ast_to_ir(&mut state) {
            let mut ir_muts = ir_mutations();
            let _ = ir_muts.mutate_all(&mut state, &mut ir_input, 0);

            if let Ok(wgsl) = ir_input.to_wgsl_string() {
                return write_out(wgsl, out_data, out_size);
            }
        }
    }

    // --------------------
    // Fallback: AST → WGSL
    // --------------------
    let wgsl = match input.to_wgsl_string() {
        Ok(s) => s,
        Err(_) => return -3,
    };

    return write_out(wgsl, out_data, out_size);

    /*
    let mut boxed = out.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    let len = boxed.len();
    std::mem::forget(boxed);

    unsafe {
        *out_data = ptr;
        *out_size = len;
    }

    0
    */
}

#[no_mangle]
pub extern "C" fn darthshader_free(ptr: *mut u8, size: usize) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        drop(Box::from_raw(slice::from_raw_parts_mut(ptr, size)));
    }
}