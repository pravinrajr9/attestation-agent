use serde::{Deserialize, Serialize};
use crate::kbc_manager::{KbcCheckInfo, KbcInterface};
use std::collections::HashMap;
use std::error::Error;
use std::net::{TcpStream};
use std::os::unix::io::{AsRawFd};
use string_error::into_err;

pub mod enclave_tls;
pub mod protocol;

use protocol::*;

#[derive(Serialize, Deserialize, Debug)]
struct AnnotationPacket {
    pub url: String,
    pub kid: String,
    pub wrapped_data: Vec<u8>,
    pub iv: Vec<u8>,
    pub wrap_type: String,
}

pub struct EAAKbc {
    pub kbs_url: String,
    pub protocol_version: String,

    pub encrypted_payload: Vec<u8>,
    pub key_id: String,
    pub iv: Vec<u8>,
    pub encrypt_type: String,

    pub kek_cache: HashMap<String, Vec<u8>>,

    pub tcp_stream: Option<TcpStream>,
    pub tls_handle: Option<enclave_tls::EnclaveTls>,
}

impl KbcInterface for EAAKbc {
    fn check(&self) -> KbcCheckInfo {
        let mut kbs_info_vec: Vec<String> = Vec::new();
        kbs_info_vec.push(self.kbs_url.clone());
        KbcCheckInfo {
            kbs_info: kbs_info_vec,
        }
    }

    fn decrypt_payload(&mut self, messages: &str) -> Result<Vec<u8>, Box<dyn Error>> {
        let annotation_packet: AnnotationPacket = serde_json::from_str(messages)?;
        self.encrypted_payload = annotation_packet.wrapped_data;
        self.key_id = annotation_packet.kid;
        self.iv = annotation_packet.iv;
        self.encrypt_type = annotation_packet.wrap_type;
        if self.kbs_url != annotation_packet.url {
            self.establish_new_kbs_connection()?;
        }
        let decrypted_payload = self.kbs_decrypt_payload()?;
        Ok(decrypted_payload)
    }
}

impl EAAKbc {
    pub fn new() -> EAAKbc {
        EAAKbc {
            kbs_url: String::new(),
            protocol_version: String::new(),
            encrypted_payload: vec![],
            key_id: String::new(),
            iv: vec![],
            encrypt_type: String::new(),
            kek_cache: HashMap::new(),
            tcp_stream: None,
            tls_handle: None,
        }
    }

    fn establish_new_kbs_connection(&mut self) -> Result<(), Box<dyn Error>> {
        self.kek_cache = HashMap::new();
        self.tls_handle = match enclave_tls::EnclaveTls::new(
            false,
            0,
            &Some("openssl".to_string()),
            &Some("openssl".to_string()),
            &Some("nullattester".to_string()),
            &Some("nullverifier".to_string()),
            true,
        ) {
            Ok(tls) => Some(tls),
            Err(_) => {
                return Err(into_err(
                    "Something wrong when recreate enclave_tls handle".to_string(),
                ))
            }
        };
        let sockaddr = get_kbs_sockaddr_from_url(&self.kbs_url)?;
        self.tcp_stream = Some(TcpStream::connect(&sockaddr[..])?);
        match self.tls_handle.as_ref().unwrap().negotiate(self.tcp_stream.as_ref().unwrap().as_raw_fd()) {
            Ok(()) => {
                self.protocol_version = self.kbs_query_version()?;
                return Ok(());
            }
            Err(_) => {
                return Err(into_err(
                    "Something wrong when negotiate enclave_tls".to_string(),
                ))
            }
        };
    }

    fn kbs_query_version(&mut self) -> Result<String, Box<dyn Error>> {
        let request = VersionRequest {
            command: String::from("version"),
        };
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();
        let reciv_string: String = self.kbs_trans_and_reciv(trans_data, "Version")?;
        let response: VersionResponse =
            serde_json::from_str::<VersionResponse>(reciv_string.as_str())?;
        match response.status.as_str() {
            "OK" => return Ok(response.version),
            "Fail" => {
                return Err(into_err(
                    "The VersionResponse status is 'Fail'!".to_string(),
                ))
            }
            _ => {
                return Err(into_err(
                    "Can't understand the VersionResponse status!".to_string(),
                ))
            }
        }
    }

    fn kbs_decrypt_payload(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let request = DecryptionRequest {
            command: String::from("Decrypt"),
            blobs: vec![Blob {
                kid: self.key_id.clone(),
                encrypted_data: base64::encode(&self.encrypted_payload),
                algorithm: "AES".to_string(),
                key_length: 256,
                iv: base64::encode(&self.iv),
            }],
        };
        let trans_json = serde_json::to_string(&request)?;
        println!("decryption transmit data: {:?}", trans_json);
        let trans_data: &[u8] = trans_json.as_bytes();
        let reciv_string: String = self.kbs_trans_and_reciv(trans_data, "Dcryption")?;
        let response: DecryptionResponse =
            serde_json::from_str::<DecryptionResponse>(reciv_string.as_str())?;
        let payload_hashmap = match response.status.as_str() {
            "OK" => response.data,
            "Fail" => return Err(into_err(response.error.unwrap())),
            _ => {
                return Err(into_err(
                    "Can't understand the DcryptionResponse status!".to_string(),
                ))
            }
        };
        if let Some(hashmap_content) = payload_hashmap {
            let encrypted_payload_string = base64::encode(&self.encrypted_payload);
            let decrypted_payload_string = match hashmap_content.get(&encrypted_payload_string) {
                Some(d) => d,
                None => return Err(into_err(
                    "There is no field matching the encrypted payload in the data field of DcryptionResponse".to_string(),
                )),
            };
            let decrypted_payload = base64::decode(decrypted_payload_string)?;
            return Ok(decrypted_payload);
        } else {
            return Err(into_err(
                "DecryptionResponse status is OK but the data is null!".to_string(),
            ));
        }
    }

    fn kbs_get_kek(&mut self) -> Result<(), Box<dyn Error>> {
        let request = GetKekRequest {
            command: String::from("Get KEK"),
            kids: vec![self.key_id.clone()],
        };
        let trans_json = serde_json::to_string(&request)?;
        let trans_data: &[u8] = trans_json.as_bytes();
        let reciv_string: String = self.kbs_trans_and_reciv(trans_data, "Get KEK")?;
        let response: GetKekResponse =
            serde_json::from_str::<GetKekResponse>(reciv_string.as_str())?;
        let kek_hashmap = match response.status.as_str() {
            "OK" => response.data,
            "Fail" => return Err(into_err(response.error.unwrap())),
            _ => {
                return Err(into_err(
                    "Can't understand the GetKekResponse status!".to_string(),
                ))
            }
        };
        if let Some(hashmap_content) = kek_hashmap {
            for (kid, kek_string) in &hashmap_content {
                let kek = base64::decode(kek_string)?;
                self.kek_cache.insert(kid.to_string(), kek);
            }
        } else {
            return Err(into_err(
                "GetKekResponse status is OK but the key is null!".to_string(),
            ));
        }
        Ok(())
    }

    fn kbs_trans_and_reciv(
        &mut self,
        trans_data: &[u8],
        error_info: &str,
    ) -> Result<String, Box<dyn Error>> {
        let _len_trans = match self.tls_handle.as_ref().unwrap().transmit(trans_data) {
            Ok(len) => len,
            Err(e) => {
                return Err(into_err(
                    format!("Something wrong when transmit {}, error code: {}", error_info, e).to_string(),
                ))
            }
        };
        let mut buffer = [0u8; 4096];
        let len_reciv = match self.tls_handle.as_ref().unwrap().receive(&mut buffer) {
            Ok(len) => len,
            Err(e) => {
                return Err(into_err(
                    format!("Something wrong when recieve {}, error code: {}", error_info, e).to_string(),
                ))
            }
        };
        let reciv_string: String = String::from_utf8(buffer[..len_reciv].to_vec())?;
        Ok(reciv_string)
    }
}

fn get_kbs_sockaddr_from_url(kbs_url: &str) -> Result<String, Box<dyn Error>> {
    // TODO
    Ok("127.0.0.1:1122".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt_payload() {
        let plain_payload: Vec<u8> = [101, 121, 74, 122, 107, 87, 69, 112, 122, 83, 87, 
        112, 118, 97, 87, 70, 73, 85, 106, 66, 106, 83, 69, 48, 50, 84, 72, 107, 53, 99, 
        108, 112, 89, 97, 51, 82, 106, 83, 69, 112, 50, 90, 71, 49, 115, 97, 49, 112, 
        89, 83, 88, 90, 104, 77, 108, 89, 49, 84, 70, 104, 87, 77, 61, 61].to_vec();

        let encrypted_payload: Vec<u8> = [244, 176, 166, 37, 9, 240, 84, 85, 236, 190, 
        165, 125, 208, 226, 30, 189, 79, 212, 58, 48, 4, 184, 245, 145, 180, 221, 25, 55, 
        165, 131, 104, 74, 100, 79, 210, 231, 183, 60, 129, 69, 16, 55, 85, 227, 127, 118, 
        178, 88, 222, 135, 176, 14, 124, 89, 24, 226, 129, 127, 47, 193, 42, 219, 237, 
        127, 12, 77, 107, 86, 214, 164, 111, 47, 107, 101, 91, 173, 208, 99, 230, 154].to_vec();

        let kek: Vec<u8> = [217, 155, 119, 5, 176, 186, 122, 22, 130, 149, 179, 163, 54, 114, 
        112, 176, 221, 155, 55, 27, 245, 20, 202, 139, 155, 167, 240, 163, 55, 17, 218, 234].to_vec();

        let iv: Vec<u8> = [116, 235, 143, 99, 70, 83, 228, 96, 9, 250, 168, 201, 234, 13, 84, 211].to_vec();

        let annotation = AnnotationPacket {
            url: "http://key-url-example/zhangjiale".to_string(),
            kid: "676913bf-9af2-4bbd-bee9-25359e2ca2e6".to_string(),
            wrapped_data: encrypted_payload,
            iv: iv,
            wrap_type: "aesm256-cbc".to_string(),
        };

        let mut eaa_kbc = EAAKbc::new();

        assert_eq!(
            eaa_kbc.decrypt_payload(
                &serde_json::to_string(&annotation).unwrap()
            ).unwrap(),
            plain_payload
        );
    }
}