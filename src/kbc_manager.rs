// Copyright (c) 2021 Alibaba Cloud
//
// SPDX-License-Identifier: Apache-2.0
//

use std::collections::HashMap;
use std::error::Error;
use std::sync::Arc;
use std::sync::Mutex;
use string_error::into_err;

use super::kbc_modules;

// KbcInterface is a standard interface that all KBC modules need to implement.
pub trait KbcInterface {
    fn check(&self) -> KbcCheckInfo;
    fn decrypt_payload(&mut self, messages: &str) -> Result<Vec<u8>, Box<dyn Error>>;
}

// KbcCheckInfo is used by KBC module instances to report their internal status to AA.
pub struct KbcCheckInfo {
    pub kbs_info: Vec<String>,
    // In the future, more KBC status fields will be expanded here.
}

lazy_static! {
    pub static ref KBC_MANAGER: Arc<Mutex<KbcManager>> = Arc::new(Mutex::new(KbcManager::new()));
}

pub struct KbcManager {
    kbc_instance_list: HashMap<String, Box<dyn KbcInterface + Sync + Send>>,
}

impl KbcManager {
    pub fn new() -> KbcManager {
        KbcManager {
            kbc_instance_list: HashMap::new(),
        }
    }

    // This method is called when AA starts.
    // It will create and instantiate all KBC modules supported by AA,
    // and register them into the kbc_instance_list of KBC_MANAGER.
    // The list of KBC modules supported by AA is the feature default field specified at compile time,
    // please refer to ../Cargo.toml for details
    pub fn init(&mut self) {
        ()
    }

    pub fn call_kbc_decrypt(
        &mut self,
        kbc_name: &str,
        messages: &str,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let kbc_instance = match self.kbc_instance_list.get_mut(kbc_name) {
            Some(instance) => instance,
            None => return Err(into_err("AA does not support the given KBC".to_string())),
        };
        let plain_payload = kbc_instance.decrypt_payload(messages)?;
        Ok(plain_payload)
    }
}

// AA expects the received DC parameter format is:
// "dc":{
//     "Parameters":{
//         "kata_cc_attestation_agent":["<kbc_name(base64encode)>"]
//      }
//  }
// fn kbc_get_name will receive the parameters field and parse it to get KBC name
pub fn kbc_get_name(parameters: HashMap<String, Vec<String>>) -> Result<String, Box<dyn Error>> {
    let parameter_list = match parameters.get("kata_cc_attestation_agent") {
        Some(list) => list,
        None => {
            return Err(into_err(
                "The request is not sent to attention agent!".to_string(),
            ))
        }
    };
    let kbc_name_byte = base64::decode(parameter_list[0].clone())?;
    let kbc_name = std::str::from_utf8(&kbc_name_byte)?;
    Ok(String::from(kbc_name))
}
