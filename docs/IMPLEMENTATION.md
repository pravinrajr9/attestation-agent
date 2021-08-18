### About the Port number that AA listens to as a grpc service

In the container image decryption operation of kata cc V0 architecture, ocicrypt-rs parses the configuration file`/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf` to obtain the port number of the keyprovider, for example:

```
{
    "key-providers": {
        "attestation-agent": {
            "grpc": "127.0.0.1:$port"
        }
    }
}
```

<<<<<<< HEAD
At present, the implementation of AA adopts the scheme of obtaining IP and port from the input parameters at startup. If there are no startup parameters, it will listen to the fixed address 127.0.0.1:44444.
=======
At present, the implementation of AA adopts the scheme of listening to the fixed port number 44444.
>>>>>>> 8eba875 (Add docs dir and IMPLEMENTATION.md)

### gRPC and ttRPC

Compared with gRPC, ttRPC has the advantage of lighter weight. AA, as a memory resident service on the client side of kata cc V0 architecture, using lightweight ttRPC will save more resources. At present, grpc is used for end-to-end testing. Wait until ocicrypt-rs supports ttrpc, AA can cooperate with the modification. Later, AA can make the use of grpc/ttrpc configurable at compile time. This needs to be discussed with the developers of ocicrypt rs.

### KBC

KBS is platform specific implementation, so AA needs to define and implement a modularization framework to allow platform providers to communicate with their own KBS infrastructure through a corresponding KBC integrated to AA.

In this scheme, each KBC module needs to realize the following functions:

- Function 1: implement a platform specific client for KBS.
  AA doesn't need to care about the detail of communication protocol between KBS and KBC. The KBC selection can be done in this way:

  ```
  {
    "op": "keyunwrap",
    "keyunwrapparams": {
      "dc": "kata_cc_attestation_agent:kbc=my_kbc",
      "annotation": "{ \"url\": \"https://$domain:port/api/getkey\", \"keyid\": \"foo\", \"payload\": \"encrypted_PLBCO\" }"
    }
  }
  ```

- Function 2: define and implement the communication protocol between KBS and KBC.
  Include application protocol, transport type, API scheme, input and output parameters, etc.

- Function 3: implement the corresponding attester logic for all potentially supported HW-TEE types
  AA, as the role defined by [RATS architecture](https://datatracker.ietf.org/doc/html/draft-ietf-rats-architecture-12.txt), is responsible for collecting evidence about the TCB status from the attesting environment and reporting it to the verifier or relying party for verification. The purpose is to convince tenant that the workload is indeed running in a genuine HW-TEE. In order to establish the binding between evidence (called quote in TDX) and user-defined data structure (aka Enclave Held Data, EHD for short), the hash of EHD is embedded into evidence and then the evidence plus EHD is sent to remote peer. Usually, EHD is a public key used for wrapping a secret.

### sample KBC

At the current stage, the sample KBC module uses hard coded KEK for decryption. In the formal scenario, the KBC module needs to parse the annotation field passed by ocicrypt-rs, obtain the connection address information of the key broker service (KBS) and the ID of the KEK, and then communicate with KBS to actually decrypt the payload (Image encryption key) in the annotation field.
