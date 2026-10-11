# Node-key recovery

An authenticated registration response with `NodeKeyExpired` stages a replacement WireGuard node key in NVS. It preserves the machine identity, discovery identity, peer cache, and application settings. It does not erase the NVS partition. A failed storage operation stops recovery and reports an error.

The running instance retains its original key. After staging, `microlink_node_key_restart_required()` returns true and the coordinator requests shutdown. The caller must stop and destroy that instance, then initialize a new instance. `microlink_start()` rejects reuse of the old context, even after successful shutdown. The ESPHome wrapper performs this replacement after cleanup succeeds. The Crosspoint prototype requires a catalog Retry or a restart.

One versioned NVS blob holds the candidate private key, its predecessor's public key, and a pending flag. A reset before acceptance reloads the same candidate. Registration includes `OldNodeKey` while the candidate remains pending. A second expiry response for an unaccepted candidate stops recovery rather than generating keys repeatedly. An `AuthURL` response retains the candidate and retries registration after reconnect backoff. A successful registration clears the pending flag in NVS before map retrieval. A later expiry can then stage another replacement.

Empty, incomplete, oversized, or malformed registration responses do not establish acceptance. HTTP/2 framing accepts an empty final DATA frame and preserves trailing transport bytes for the subsequent map exchange. Nonempty registration errors take precedence over other status fields. Nonempty node-key signatures produce an unsupported Tailnet Lock error; this check does not implement Tailnet Lock or detect every locked-tailnet configuration.

Node-key regeneration does not guarantee re-enrollment. An expired or consumed enrollment key, device approval, or server policy can prevent acceptance. The pending record is retained on failure. NVS storage is not encrypted by this patch, and physical access can expose private keys. Firmware downgrade to a version that ignores the replacement record can reuse the obsolete legacy key; downgrade after rotation is unsupported.

The client submits a configured enrollment key on registration. It does not automatically discard a refused key. In the controlled S3 test, the old enrollment key was refused for the replacement; an empty enrollment key produced an approval URL. After the user approved that URL, the saved replacement registered successfully. Recovery can therefore require a fresh enrollment key or removal of the stale key followed by interactive approval.

## Validation

Run `tests/run-nodekey-tests` with a host C compiler. It compiles the production persistence code and X25519 implementation with address and undefined-behavior sanitizers. The fake NVS backend checks bounded staging, acceptance, a later rotation, malformed records, write failures, and reset-time reload. It rejects writes to unrelated keys.

Run `tests/run-registration-tests` with `IDF_PATH` set to the ESP-IDF checkout. It compiles the production registration classifier and frame parser with sanitizers. Cases include response precedence, invalid status types, partial frames, empty final DATA, padding, response capacity, and trailing transport bytes.

The native S3 harness verified that the new identity loader preserves the existing tailnet address. Its lifecycle probe verified rejection of a same-instance restart after the replacement flag is set and completed three connected stop/destroy cycles. A controlled replacement survived refusal of the old enrollment key and a reboot before manual approval. After approval, the accepted record survived reinitialization, retained the VPN address, and completed a 256 KiB tailnet download with the expected SHA-256. Approval registered the device under the user's identity with no tags. These checks do not establish server-generated expiry recovery, uninterrupted approval polling, or a later second expiry.
