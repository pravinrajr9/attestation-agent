// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

#[macro_use]
extern crate lazy_static;
use std::env;
use std::error::Error;
use string_error::into_err;

#[cfg(feature = "grpc")]
pub mod grpc;

pub mod kbc_manager;
pub mod kbc_modules;

fn init_kbc_manager() -> Result<(), Box<dyn Error>> {
    let mut kbc_manager = kbc_manager::KBC_MANAGER.lock()?;
    kbc_manager.init();
    drop(kbc_manager);
    Ok(())
}

fn parse_args_get_addr(args: Vec<String>) -> Result<(String, u16), Box<dyn Error>> {
    let mut ip = String::new();
    let mut port: u16 = 0;

    if args.len() == 1 {
        ip = "127.0.0.1".to_string();
        port = 44444;
    } else if args.len() == 2 {
        let addr = &args[1];
        if let Some(index) = addr.find(':') {
            ip = addr.chars().take(index).collect();
            let port_string: String = addr.chars().skip(index + 1).collect();
            port = port_string.parse::<u16>()?;
            // println!("ip: {}, port: {}", ip, port);
        } else {
            return Err(into_err(
                "Please input correct address of the service!
                example: 'attestation-agent 127.0.0.1:1122'"
                    .to_string(),
            ));
        }
    } else {
        return Err(into_err(
            "Please input correct arguments!
            example: 'attestation-agent 127.0.0.1:1122'"
                .to_string(),
        ));
    }

    Ok((ip, port))
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let (ip, port) = match parse_args_get_addr(args) {
        Ok((ip, port)) => (ip, port),
        Err(e) => {
            println!("Parse arguments wrong: {}", e);
            return ();
        }
    };

    // Initialize the KBC manager module,
    // and create all supported KBC instances.
    match init_kbc_manager() {
        Ok(()) => (),
        Err(e) => {
            println!("Something wrong when init kbc manager: {}", e);
            return ();
        }
    }
/*
    // When the gRPC compilation option is used,
    // create a gRPC service of the key provider.
    #[cfg(feature = "grpc")]
    match grpc::start_grpc_service(ip, port) {
        Ok(()) => (),
        Err(e) => {
            println!("Something wrong when start grpc service: {}", e);
            return ();
        }
    }
*/
    kbc_modules::eaa_sgx_kbc::enclave_test();
}
