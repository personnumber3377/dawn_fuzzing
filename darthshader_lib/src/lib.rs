#![allow(clippy::missing_safety_doc)]

#![feature(variant_count)]


pub mod ast;
pub mod layeredinput;
pub mod mini_state;

// IR stuff:

pub mod ir;
pub mod generator;


mod randomext;
mod ffi;

pub use ffi::{darthshader_free, darthshader_mutate};