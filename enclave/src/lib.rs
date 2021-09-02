// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "helloworldsampleenclave"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;

use serde::{Deserialize, Serialize};
use sgx_types::*;
use std::collections::HashMap;
use std::error::Error;
use std::io::{self, Write};
use std::net::TcpStream;
use std::ops::{Deref, DerefMut};
use std::os::raw::c_char;
use std::os::unix::io::{AsRawFd, RawFd};
use std::ptr::NonNull;
use std::slice;
use std::string::String;
use std::vec::Vec;
use std::sys_common::AsInner;

mod enclave_tls;
mod foreign_types_sgx;
mod protocol;
mod string_error_sgx;

use foreign_types_sgx::{ForeignType, ForeignTypeRef, Opaque};
use protocol::*;
use string_error_sgx::into_err;

extern "C" {
    fn test(val: i32) -> i32;
}

#[no_mangle]
pub extern "C" fn say_something(
    some_string: *const u8,
    some_len: usize,
    enclave_id: sgx_enclave_id_t,
) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);
    let rust_raw_string = "This is a in-Enclave ";
    let word: [u8; 4] = [82, 117, 115, 116];
    let word_vec: Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];
    let mut hello_string = String::from(rust_raw_string);
    for c in word.iter() {
        hello_string.push(*c as char);
    }
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8").as_str();
    println!(
        "{}, {}, enclave id: {:?}",
        &hello_string,
        unsafe { test(66666) },
        enclave_id
    );

    test_query_version();

    sgx_status_t::SGX_SUCCESS
}

fn test_query_version() {
    let request = VersionRequest {
        command: String::from("version"),
    };
    let trans_json = serde_json::to_string(&request).unwrap();
    let trans_data: &[u8] = trans_json.as_bytes();

    
    let tls_handle = enclave_tls::EnclaveTls::new(
        false,
        0,
        &Some(String::from("openssl")),
        &Some(String::from("openssl")),
        &Some(String::from("nullattester")),
        &Some(String::from("nullverifier")),
        true,
    ).unwrap();

    /*
    let sockaddr = "127.0.0.1:1122";
    let tcp_stream = TcpStream::connect(sockaddr).unwrap();
    tls_handle.negotiate(*tcp_stream.as_inner().socket().as_inner());

    let _len_trans = tls_handle.transmit(trans_data).unwrap();
    let mut buffer = [0u8; 4096];
    let _len_reciv = tls_handle.receive(&mut buffer).unwrap();

    let reciv_string: String = String::from_utf8(buffer[.._len_reciv].to_vec()).unwrap();
    println!("reciv_string: {}", reciv_string);
    */
}
