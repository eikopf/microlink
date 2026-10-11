# Network-switch shutdown

The optional Wi-Fi/cellular manager retains its MicroLink instance when `microlink_stop()` fails. It stops the transition instead of changing transport or allocating a replacement. Application code must retry `ml_net_switch_stop()` before restarting or deinitializing the manager.

Stop requests cancel Wi-Fi waiting and the manager's retry delay. Cellular connection setup can remain blocked until the modem operation returns. `ml_net_switch_stop()` waits up to 15 seconds for the manager's exit acknowledgement; a timeout retains the manager, instance, transports, event group, and configuration. After that acknowledgement, VPN cleanup can itself take up to 15 seconds. A failed VPN cleanup also retains the instance and transports. The application can retry after outstanding work exits.

Health and failback timer callbacks post event bits. The manager task reads VPN state and performs transitions. Timer callbacks do not dereference the VPN owner. Deinitialization queues timer deletion and one completion callback, then waits for that callback before deleting the event group. A timed-out deinit retains the same pending completion across retries. It does not queue another callback. Wi-Fi event handlers are unregistered before freeing their event group and interface.

The application must serialize lifecycle calls and invoke them outside module callbacks and the FreeRTOS timer task. Starting during retained cleanup or partial deinitialization returns `ESP_ERR_INVALID_STATE`. The deinit API remains void; it logs incomplete VPN shutdown and retains resources for a later retry.

## Validation

`tests/run-net-switch-tests` compiles the production manager and its public header against host platform stubs with address and undefined-behavior sanitizers. It checks manager-exit timeout, VPN-stop timeout, retained ownership, refusal to allocate a replacement, timer callbacks that do not read the owner, and delayed timer completion across repeated deinit calls. The stubs do not model real RTOS scheduling or modem behavior.

The S3 transport harness and Crosspoint profile disable this module. The available board has no cellular modem, so no cellular failover or shutdown hardware result is claimed. A separate native build with cellular support, PPP, and network switching enabled compiles successfully with `-Werror=all` and no warning override. The binary is not flashed to the board.

The enabled build exposed a separate AT-socket address bug. Unsupported families left the port and address text uninitialized; truncated addresses were read without checking their supplied length. `ml_at_connect()` and UDP `ml_at_sendto()` now validate addresses before constructing modem commands. `tests/run-at-address-tests` exercises the production conversion helper with sanitizers, including IPv4, IPv6, every truncated length, unaligned input, unsupported families, and insufficient output space. IPv6 scope IDs remain unsupported.
