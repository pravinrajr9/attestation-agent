extern crate serde;

use self::serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::vec::Vec;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyProviderInput {
    op: String,
    pub keywrapparams: KeyWrapParams,
    pub keyunwrapparams: KeyUnwrapParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapParams {
    pub ec: Option<Ec>,
    pub optsdata: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Ec {
    pub Parameters: HashMap<String, Vec<Vec<u8>>>,
    pub DecryptConfig: Option<Dc>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapOutput {
    pub keywrapresults: KeyWrapResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyWrapResults {
    pub annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapParams {
    pub dc: Option<Dc>,
    pub annotation: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Dc {
    pub Parameters: HashMap<String, Vec<Vec<u8>>>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapOutput {
    pub keyunwrapresults: KeyUnwrapResults,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyUnwrapResults {
    pub optsdata: Vec<u8>,
}
