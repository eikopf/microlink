#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "nvs.h"

/* ESP_ERR_NVS_NOT_FOUND means the legacy keypair remains authoritative. */
esp_err_t ml_nodekey_load(nvs_handle_t nvs, uint8_t private_key[32],
                         uint8_t public_key[32], uint8_t old_public_key[32], bool *pending);

/* Persist a replacement for the next instance; never change a live keypair. */
esp_err_t ml_nodekey_stage(const uint8_t private_key[32], const uint8_t public_key[32]);

/* Mark the persisted replacement accepted after successful registration. */
esp_err_t ml_nodekey_accept(const uint8_t private_key[32]);
