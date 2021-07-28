// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use futures::channel::oneshot;
use futures::executor::block_on;
use futures::prelude::*;
use grpcio::{Environment, ServerBuilder};
use std::error::Error;
use std::io::Read;
use std::str;
use std::sync::Arc;
use std::{io, thread};
use string_error::into_err;

pub mod grpc_keyprovider;

use grpc_keyprovider::keyprovider;
use grpc_keyprovider::keyprovider_grpc::*;
use grpc_keyprovider::keyprovider_structs::*;

use super::kbc_manager;

#[derive(Clone)]
pub struct KeyProvider;

impl KeyProviderService for KeyProvider {
    fn un_wrap_key(
        &mut self,
        ctx: ::grpcio::RpcContext,
        req: keyprovider::keyProviderKeyWrapProtocolInput,
        sink: ::grpcio::UnarySink<keyprovider::keyProviderKeyWrapProtocolOutput>,
    ) {
        // Deserialize gRPC input to get kbs_annotation_packet.
        let (annotation, dc) =
            match get_annotation_and_dc_from_input(req.KeyProviderKeyWrapProtocolInput) {
                Ok((a, d)) => (a, d),
                Err(e) => {
                    println!(
                        "Some error happend when get annotation and dc from input: {}",
                        e
                    );
                    return ();
                }
            };

        // Parse the DC parameter in gRPC input and get the KBC name to be selected.
        // For details on DC parameter,
        // please refer to kbc_get_name function in kbc_manager.rs.
        let kbc_name_string: String = match kbc_manager::kbc_get_name(dc.Parameters) {
            Ok(name) => name,
            Err(e) => {
                println!("Some error happend when get kbc name from Dc: {}", e);
                return ();
            }
        };

        // Select the KBC module instance,
        // and pass the annotation to the KBC module for content parsing and field decryption.
        let mut kbc_manager = match kbc_manager::KBC_MANAGER.lock() {
            Ok(manager) => manager,
            Err(e) => {
                println!("Some error happend when access kbc manager(Mutex): {}", e);
                return ();
            }
        };
        let decrypted_optsdata =
            match kbc_manager.call_kbc_decrypt(&kbc_name_string[..], &annotation[..]) {
                Ok(data) => data,
                Err(e) => {
                    println!(
                        "Some error happend when call kbc to decrypt optsdata: {}",
                        e
                    );
                    return ();
                }
            };
        drop(kbc_manager);

        // Construct output structure and serialize it as the return value of gRPC
        let output_struct = KeyUnwrapOutput {
            keyunwrapresults: KeyUnwrapResults {
                optsdata: decrypted_optsdata,
            },
        };
        let mut result = keyprovider::keyProviderKeyWrapProtocolOutput::new();
        match serde_json::to_string(&output_struct) {
            Ok(output_string) => {
                result.KeyProviderKeyWrapProtocolOutput = output_string.as_bytes().to_vec();
            }
            Err(e) => {
                println!("Some error happend when serialize the output struct: {}", e);
                return ();
            }
        }
        let output = sink
            .success(result.clone())
            .map_err(move |err| eprintln!("Failed to reply: {:?}", err))
            .map(move |_| println!("Responded with result {{ {:?} }}", result));
        ctx.spawn(output)
    }
}

fn get_annotation_and_dc_from_input(input_byte: Vec<u8>) -> Result<(String, Dc), Box<dyn Error>> {
    let input_string = String::from_utf8(input_byte)?;
    let input: KeyProviderInput = serde_json::from_str::<KeyProviderInput>(&input_string[..])?;
    let base64_annotation = match input.keyunwrapparams.annotation {
        Some(a) => a,
        None => {
            return Err(into_err(
                "The annotation field in the input is None!".to_string(),
            ))
        }
    };
    let vec_annotation = base64::decode(base64_annotation)?;
    let jsonstring_annotation: &str = str::from_utf8(&vec_annotation)?;
    let dc = match input.keyunwrapparams.dc {
        Some(d) => d,
        None => return Err(into_err("The Dc field in the input is None!".to_string())),
    };

    Ok((jsonstring_annotation.to_string(), dc))
}

pub fn start_grpc_service(ip: String, port: u16) -> Result<(), Box<dyn Error>> {
    let env = Arc::new(Environment::new(1));
    let service = create_key_provider_service(KeyProvider);
    let mut server = ServerBuilder::new(env)
        .register_service(service)
        .bind(&ip, port)
        .build()?;

    server.start();

    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        println!("Press ENTER to exit...");
        match io::stdin().read(&mut [0]) {
            Ok(_) => (),
            Err(_) => panic!("Exit command unexpect!"),
        };
        tx.send(())
    });
    let _ = block_on(rx);
    let _ = block_on(server.shutdown());

    Ok(())
}
