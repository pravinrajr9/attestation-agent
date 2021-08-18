// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::kbc_manager::{KbcCheckInfo, KbcInterface};

use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};
use std::error::Error;
use string_error::into_err;

// KBS specific packet
#[derive(Serialize, Deserialize, Debug)]
pub struct AnnotationPacket {
    // The access information of KBS is passed to KBC module through annotation.
    // key_url is used as an example here.
    pub key_url: String,
    pub wrapped_key: Vec<u8>,
    pub wrap_type: String,
}

pub struct SampleKbc {
    encrypted_payload: Vec<u8>,
    kbs_info: Vec<String>,
}

// As a KBS client for attestation-agent,
// it must implement KbcInterface trait.
impl KbcInterface for SampleKbc {
    fn check(&self) -> KbcCheckInfo {
        KbcCheckInfo {
            kbs_info: self.kbs_info.clone(),
        }
    }

    fn decrypt_payload(&mut self, messages: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        // Parse the annotation, and obtain the access information of KBS and the field content to be decrypted.
        let annotation_packet: AnnotationPacket = serde_json::from_str(messages)?;
        self.kbs_info.push(annotation_packet.key_url);
        self.encrypted_payload = annotation_packet.wrapped_key;

        let cipher_text: &Vec<u8> = &self.encrypted_payload;
        let decrypting_key = Key::from_slice(b"passphrasewhichneedstobe32bytes!");
        let cipher = Aes256Gcm::new(decrypting_key);
        let nonce = Nonce::from_slice(b"unique nonce");

        let plain_text = match cipher.decrypt(nonce, cipher_text.as_ref()) {
            Ok(text) => text,
            Err(_) => return Err(into_err("Decrypt failed!".to_string())),
        };

        Ok(plain_text)
    }
}

impl SampleKbc {
    pub fn new() -> SampleKbc {
        SampleKbc {
            encrypted_payload: vec![],
            kbs_info: vec![],
        }
    }
}
