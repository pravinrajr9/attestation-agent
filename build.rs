// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

fn main() {
    #[cfg(feature = "grpc")]
    {
        let proto_root = "src/grpc/grpc_keyprovider";
        println!("cargo:rerun-if-changed={}", proto_root);
        protoc_grpcio::compile_grpc_protos(
            &["proto/keyprovider.proto"],
            &[proto_root],
            &proto_root,
            None,
        )
        .expect("Failed to compile gRPC definitions!");
    }

    #[cfg(feature = "eaa_kbc")]
    {
        println!("cargo:rustc-link-search=native=/opt/enclave-tls/lib");
        println!("cargo:rustc-link-lib=dylib=enclave_tls");
    }

    return ();
}
