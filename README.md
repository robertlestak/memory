# memory

`memory` is an interface for scalable memory access with a focus on at rest and in transit encryption. It is designed to be used in environments where the runtime memory is not trusted, such as in a cloud environment, or when processing sensitive data.

`memory` supports multiple backends, including an in-process `memory` backend, `redis`, and `file`. It is designed to be extensible to support other backends with ease.

At start-up, `memory` will accept a private key and a backend configuration. It will then initialize the backend and use the private key to encrypt and decrypt data in the backend. Once loaded into memory, the private key file is deleted from disk. Optionally, the private key can be provided as an enviornment variable, or via TTY input at start-up. Data is encrypted locally before being sent to the backend, and decrypted locally after being retrieved from the backend.

`memory` can be used both as a library and as a REST API service. Note that when used in the REST server mode, you are responsible for ensuring intra-service encryption. It's recommended to only use this in environments which default secure, such as in an Istio Service Mesh with strict mTLS enabled. Whereas in library mode all encryption is done within the application in question, in server mode, the raw data is sent across the wire (ideally encrypted in transit) before it is encrypted at the `memory` service layer. This means that clients of the REST service do not need to manage private keys, but also means that any client with access to the `memory` service can read the data stored in the backend.
