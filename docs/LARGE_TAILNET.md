# Capacity and memory

The tested S3 configuration uses 16 peer slots and 64 KiB HTTP/2 and JSON buffers for an eight-peer tailnet. These values are evidence for that configuration, not a scaling guarantee.

`CONFIG_ML_MAX_PEERS` bounds the client peer table and WireGuard peer capacity. A low limit can exclude the intended server even when only one application connection is needed. Peer visibility in the coordinator map and active application connections are different quantities.

`CONFIG_ML_NVS_MAX_PEERS` bounds persisted peer metadata. Increasing it can require a larger NVS partition. `CONFIG_ML_H2_BUFFER_SIZE_KB` and `CONFIG_ML_JSON_BUFFER_SIZE_KB` bound control-plane buffering. Required memory depends on map size and policy complexity, not just peer count.

The receive filter permits eight named groups and 128 expanded rows. Unsupported or oversized policies fail closed. The DERP pool permits two destination regions in addition to home. Each live connection also allocates TLS resources.

Measured native S3 free internal heap with three relay connections was approximately 128 KiB, with a largest free block of 52 KiB. These snapshots include changing control-plane allocations and do not isolate relay cost. They do not establish headroom for a reader application or a C3.

Large-tailnet and C3 runtime tests are pending. Configure limits against the actual map, observe peak memory usage, and test the required destinations before relying on a deployment.
