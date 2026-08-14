#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bootloader_random.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "driver/ledc.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"
#include "nvs.h"
#include "nvs_flash.h"

#define FRAME_MAX 8192
#define TEXT_MAX 4096
#define DEVICE_ID_MAX 96
#define KID_LEN 66
#define CAPABILITY_ID_LEN 78
#define DIGEST_LEN 71
#define COMMAND_ID_LEN 99
#define NONCE_LEN 24
#define DOMAIN "KINEGRANT-SIGNED-ENVELOPE-V1\0"
#define PROFILE "kgp-esp32c3-paper-barrier/0.1"
#define COMMAND_TYPE "kinegrant:ExperimentalDeviceCommand"
#define ACK_TYPE "kinegrant:ExperimentalDeviceAck"
#define CHALLENGE_TYPE "kinegrant:ExperimentalDeviceChallenge"
#define CHALLENGE_US 10000000LL
#define SERVO_GPIO GPIO_NUM_4
#define SERVO_CLOSED_US 1100U
#define SERVO_OPEN_US 1900U
#define SERVO_PERIOD_US 20000U
#define SERVO_HOLD_MS 600U

typedef struct {
    char device_id[DEVICE_ID_MAX + 1];
    char executor_kid[KID_LEN + 1];
    char device_kid[KID_LEN + 1];
    uint8_t device_secret[64];
    uint32_t boot_counter;
    uint32_t last_sequence;
    uint32_t actuator_count;
    char challenge_nonce[NONCE_LEN + 1];
    int64_t challenge_issued_us;
} device_state_t;

typedef struct {
    char kid[KID_LEN + 1];
    char capability_id[CAPABILITY_ID_LEN + 1];
    char request_digest[DIGEST_LEN + 1];
    char command_id[COMMAND_ID_LEN + 1];
    char position[7];
    uint32_t boot_counter;
    uint32_t sequence;
} command_t;

static bool copy_text(char *out, size_t out_size, const cJSON *item) {
    if (!cJSON_IsString(item) || item->valuestring == NULL) return false;
    size_t size = strlen(item->valuestring);
    if (size == 0 || size >= out_size) return false;
    memcpy(out, item->valuestring, size + 1);
    return true;
}

static bool exact_keys(const cJSON *object, const char *const *keys, size_t count) {
    if (!cJSON_IsObject(object)) return false;
    const cJSON *child = object->child;
    for (size_t i = 0; i < count; ++i) {
        if (child == NULL || child->string == NULL || strcmp(child->string, keys[i]) != 0) {
            return false;
        }
        child = child->next;
    }
    return child == NULL;
}

static bool positive_u32(const cJSON *item, uint32_t *out) {
    if (!cJSON_IsNumber(item) || item->valuedouble < 1.0 ||
        item->valuedouble > 4294967295.0) return false;
    uint32_t value = (uint32_t)item->valuedouble;
    if ((double)value != item->valuedouble) return false;
    *out = value;
    return true;
}

static bool chars_match(const char *value, const char *alphabet, size_t exact_len) {
    if (value == NULL || strlen(value) != exact_len) return false;
    return strspn(value, alphabet) == exact_len;
}

static bool prefixed_hex(const char *value, const char *prefix, size_t hex_len) {
    size_t prefix_len = strlen(prefix);
    return value != NULL && strlen(value) == prefix_len + hex_len &&
           memcmp(value, prefix, prefix_len) == 0 &&
           chars_match(value + prefix_len, "0123456789abcdef", hex_len);
}

static int b64_value(char value) {
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
}

static bool b64url_decode(const char *input, uint8_t *output, size_t expected) {
    size_t length = strlen(input);
    if (length == 0 || length % 4 == 1 || ((length * 6) / 8) != expected) return false;
    uint32_t bits = 0;
    unsigned available = 0;
    size_t produced = 0;
    for (size_t i = 0; i < length; ++i) {
        int value = b64_value(input[i]);
        if (value < 0) return false;
        bits = (bits << 6) | (uint32_t)value;
        available += 6;
        if (available >= 8) {
            available -= 8;
            if (produced >= expected) return false;
            output[produced++] = (uint8_t)(bits >> available);
            bits &= available == 0 ? 0U : ((1U << available) - 1U);
        }
    }
    return produced == expected && bits == 0;
}

static bool b64url_encode(const uint8_t *input, size_t input_size, char *output,
                          size_t output_size) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t needed = (input_size * 8 + 5) / 6;
    if (output_size <= needed) return false;
    uint32_t bits = 0;
    unsigned available = 0;
    size_t produced = 0;
    for (size_t i = 0; i < input_size; ++i) {
        bits = (bits << 8) | input[i];
        available += 8;
        while (available >= 6) {
            available -= 6;
            output[produced++] = alphabet[(bits >> available) & 63U];
            bits &= available == 0 ? 0U : ((1U << available) - 1U);
        }
    }
    if (available != 0) output[produced++] = alphabet[(bits << (6 - available)) & 63U];
    output[produced] = '\0';
    return produced == needed;
}

static bool make_kid(const uint8_t public_key[32], char output[KID_LEN + 1]) {
    static const char prefix[] = "kinegrant:key:ed25519:";
    memcpy(output, prefix, sizeof(prefix) - 1);
    return b64url_encode(public_key, 32, output + sizeof(prefix) - 1,
                         KID_LEN + 1 - (sizeof(prefix) - 1));
}

static bool valid_kid(const char *value, uint8_t public_key[32]) {
    static const char prefix[] = "kinegrant:key:ed25519:";
    return value != NULL && strlen(value) == KID_LEN &&
           memcmp(value, prefix, sizeof(prefix) - 1) == 0 &&
           b64url_decode(value + sizeof(prefix) - 1, public_key, 32);
}

static void sha256_hex(const uint8_t *input, size_t size, char output[65]) {
    uint8_t digest[32];
    static const char hex[] = "0123456789abcdef";
    mbedtls_sha256(input, size, digest, 0);
    for (size_t i = 0; i < sizeof(digest); ++i) {
        output[i * 2] = hex[digest[i] >> 4];
        output[i * 2 + 1] = hex[digest[i] & 15U];
    }
    output[64] = '\0';
    crypto_wipe(digest, sizeof(digest));
}

static bool snprintf_ok(int result, size_t size) {
    return result >= 0 && (size_t)result < size;
}

static bool read_frame(char frame[FRAME_MAX]) {
    size_t used = 0;
    bool overflow = false;
    for (;;) {
        int value = getchar();
        if (value == EOF) continue;
        if (value == '\r' || value == '\0') overflow = true;
        if (value == '\n') break;
        if (used + 1 >= FRAME_MAX) {
            overflow = true;
        } else {
            frame[used++] = (char)value;
        }
    }
    frame[used] = '\0';
    return !overflow && used != 0;
}

static bool load_config(device_state_t *state) {
    nvs_handle_t handle;
    if (nvs_open("kgp_config", NVS_READONLY, &handle) != ESP_OK) return false;
    size_t device_size = sizeof(state->device_id);
    size_t executor_size = sizeof(state->executor_kid);
    size_t seed_size = 32;
    uint8_t seed[32];
    esp_err_t result = nvs_get_str(handle, "device_id", state->device_id, &device_size);
    if (result == ESP_OK) {
        result = nvs_get_str(handle, "executor_kid", state->executor_kid, &executor_size);
    }
    if (result == ESP_OK) result = nvs_get_blob(handle, "device_seed", seed, &seed_size);
    nvs_close(handle);
    if (result != ESP_OK || seed_size != sizeof(seed) || device_size < 2 ||
        device_size > sizeof(state->device_id) ||
        strspn(state->device_id, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789:._-") !=
            strlen(state->device_id)) {
        crypto_wipe(seed, sizeof(seed));
        return false;
    }
    uint8_t executor_key[32];
    if (!valid_kid(state->executor_kid, executor_key)) {
        crypto_wipe(seed, sizeof(seed));
        return false;
    }
    crypto_wipe(executor_key, sizeof(executor_key));
    uint8_t device_public[32];
    crypto_ed25519_key_pair(state->device_secret, device_public, seed);
    bool ok = make_kid(device_public, state->device_kid);
    crypto_wipe(device_public, sizeof(device_public));
    return ok;
}

static bool begin_boot(device_state_t *state) {
    nvs_handle_t handle;
    if (nvs_open("kgp_state", NVS_READWRITE, &handle) != ESP_OK) return false;
    uint32_t boot = 0;
    uint32_t count = 0;
    esp_err_t result = nvs_get_u32(handle, "boot_counter", &boot);
    if (result != ESP_OK && result != ESP_ERR_NVS_NOT_FOUND) goto fail;
    result = nvs_get_u32(handle, "actuator_count", &count);
    if (result != ESP_OK && result != ESP_ERR_NVS_NOT_FOUND) goto fail;
    if (boot == UINT32_MAX || count == UINT32_MAX) goto fail;
    state->boot_counter = boot + 1;
    state->last_sequence = 0;
    state->actuator_count = count;
    if (nvs_set_u32(handle, "boot_counter", state->boot_counter) != ESP_OK ||
        nvs_set_u32(handle, "last_sequence", 0) != ESP_OK ||
        nvs_set_str(handle, "last_command", "") != ESP_OK ||
        nvs_commit(handle) != ESP_OK) goto fail;
    nvs_close(handle);
    return true;
fail:
    nvs_close(handle);
    return false;
}

static bool persist_consumption(device_state_t *state, const command_t *command) {
    if (command->sequence != state->last_sequence + 1 || state->actuator_count == UINT32_MAX) {
        return false;
    }
    nvs_handle_t handle;
    if (nvs_open("kgp_state", NVS_READWRITE, &handle) != ESP_OK) return false;
    uint32_t count = state->actuator_count + 1;
    bool ok = nvs_set_u32(handle, "last_sequence", command->sequence) == ESP_OK &&
              nvs_set_u32(handle, "actuator_count", count) == ESP_OK &&
              nvs_set_str(handle, "last_command", command->command_id) == ESP_OK &&
              nvs_commit(handle) == ESP_OK;
    nvs_close(handle);
    if (!ok) return false;
    state->last_sequence = command->sequence;
    state->actuator_count = count;
    return true;
}

static bool new_challenge(device_state_t *state) {
    if (state->last_sequence == UINT32_MAX) return false;
    uint8_t nonce[18];
    bootloader_random_enable();
    esp_fill_random(nonce, sizeof(nonce));
    bootloader_random_disable();
    bool ok = b64url_encode(nonce, sizeof(nonce), state->challenge_nonce,
                            sizeof(state->challenge_nonce));
    crypto_wipe(nonce, sizeof(nonce));
    if (!ok) return false;
    state->challenge_issued_us = esp_timer_get_time();
    printf("{\"boot_counter\":%lu,\"challenge_nonce\":\"%s\",\"device_id\":\"%s\","
           "\"max_age_ms\":10000,\"next_sequence\":%lu,\"profile\":\"%s\","
           "\"type\":\"%s\"}\n",
           (unsigned long)state->boot_counter, state->challenge_nonce, state->device_id,
           (unsigned long)(state->last_sequence + 1), PROFILE, CHALLENGE_TYPE);
    return true;
}

static bool verify_command(const char *frame, const device_state_t *state,
                           command_t *command) {
    static const char *const envelope_keys[] = {"alg", "kid", "payload", "signature"};
    static const char *const payload_keys[] = {
        "action", "boot_counter", "capability_id", "challenge_nonce", "command_id",
        "device_id", "executor", "parameters", "profile", "request_digest", "sequence", "type"};
    static const char *const parameter_keys[] = {"position"};
    cJSON *root = cJSON_ParseWithLength(frame, strlen(frame));
    if (root == NULL || !exact_keys(root, envelope_keys, 4)) goto fail;
    cJSON *alg = cJSON_GetObjectItemCaseSensitive(root, "alg");
    cJSON *kid = cJSON_GetObjectItemCaseSensitive(root, "kid");
    cJSON *payload = cJSON_GetObjectItemCaseSensitive(root, "payload");
    cJSON *signature_item = cJSON_GetObjectItemCaseSensitive(root, "signature");
    if (!cJSON_IsString(alg) || strcmp(alg->valuestring, "EdDSA") != 0 ||
        !exact_keys(payload, payload_keys, 12) ||
        !copy_text(command->kid, sizeof(command->kid), kid) ||
        strcmp(command->kid, state->executor_kid) != 0) goto fail;

    cJSON *parameters = cJSON_GetObjectItemCaseSensitive(payload, "parameters");
    if (!exact_keys(parameters, parameter_keys, 1) ||
        !copy_text(command->position, sizeof(command->position),
                   cJSON_GetObjectItemCaseSensitive(parameters, "position")) ||
        (strcmp(command->position, "open") != 0 && strcmp(command->position, "closed") != 0)) goto fail;

    char action[24], nonce[NONCE_LEN + 1], device_id[DEVICE_ID_MAX + 1];
    char executor[KID_LEN + 1], profile[40], type[48], signature_text[87];
    if (!copy_text(action, sizeof(action), cJSON_GetObjectItemCaseSensitive(payload, "action")) ||
        !copy_text(command->capability_id, sizeof(command->capability_id), cJSON_GetObjectItemCaseSensitive(payload, "capability_id")) ||
        !copy_text(nonce, sizeof(nonce), cJSON_GetObjectItemCaseSensitive(payload, "challenge_nonce")) ||
        !copy_text(command->command_id, sizeof(command->command_id), cJSON_GetObjectItemCaseSensitive(payload, "command_id")) ||
        !copy_text(device_id, sizeof(device_id), cJSON_GetObjectItemCaseSensitive(payload, "device_id")) ||
        !copy_text(executor, sizeof(executor), cJSON_GetObjectItemCaseSensitive(payload, "executor")) ||
        !copy_text(profile, sizeof(profile), cJSON_GetObjectItemCaseSensitive(payload, "profile")) ||
        !copy_text(command->request_digest, sizeof(command->request_digest), cJSON_GetObjectItemCaseSensitive(payload, "request_digest")) ||
        !copy_text(type, sizeof(type), cJSON_GetObjectItemCaseSensitive(payload, "type")) ||
        !copy_text(signature_text, sizeof(signature_text), signature_item) ||
        !positive_u32(cJSON_GetObjectItemCaseSensitive(payload, "boot_counter"), &command->boot_counter) ||
        !positive_u32(cJSON_GetObjectItemCaseSensitive(payload, "sequence"), &command->sequence)) goto fail;

    if (strcmp(action, "move_paper_barrier") != 0 || strcmp(device_id, state->device_id) != 0 ||
        strcmp(executor, command->kid) != 0 || strcmp(profile, PROFILE) != 0 ||
        strcmp(type, COMMAND_TYPE) != 0 || command->boot_counter != state->boot_counter ||
        command->sequence != state->last_sequence + 1 || strcmp(nonce, state->challenge_nonce) != 0 ||
        !prefixed_hex(command->capability_id, "kinegrant:cap:", 64) ||
        !prefixed_hex(command->request_digest, "sha256:", 64) ||
        !prefixed_hex(command->command_id, "kinegrant:device-command:", 64)) goto fail;

    char unsigned_payload[TEXT_MAX];
    int result = snprintf(unsigned_payload, sizeof(unsigned_payload),
        "{\"action\":\"move_paper_barrier\",\"boot_counter\":%lu,\"capability_id\":\"%s\","
        "\"challenge_nonce\":\"%s\",\"device_id\":\"%s\",\"executor\":\"%s\","
        "\"parameters\":{\"position\":\"%s\"},\"profile\":\"%s\",\"request_digest\":\"%s\","
        "\"sequence\":%lu,\"type\":\"%s\"}",
        (unsigned long)command->boot_counter, command->capability_id, nonce, device_id,
        executor, command->position, PROFILE, command->request_digest,
        (unsigned long)command->sequence, COMMAND_TYPE);
    if (!snprintf_ok(result, sizeof(unsigned_payload))) goto fail;
    char command_hash[65];
    sha256_hex((const uint8_t *)unsigned_payload, strlen(unsigned_payload), command_hash);
    if (strcmp(command->command_id + strlen("kinegrant:device-command:"), command_hash) != 0) goto fail;

    char canonical_payload[TEXT_MAX];
    result = snprintf(canonical_payload, sizeof(canonical_payload),
        "{\"action\":\"move_paper_barrier\",\"boot_counter\":%lu,\"capability_id\":\"%s\","
        "\"challenge_nonce\":\"%s\",\"command_id\":\"%s\",\"device_id\":\"%s\","
        "\"executor\":\"%s\",\"parameters\":{\"position\":\"%s\"},\"profile\":\"%s\","
        "\"request_digest\":\"%s\",\"sequence\":%lu,\"type\":\"%s\"}",
        (unsigned long)command->boot_counter, command->capability_id, nonce,
        command->command_id, device_id, executor, command->position, PROFILE,
        command->request_digest, (unsigned long)command->sequence, COMMAND_TYPE);
    if (!snprintf_ok(result, sizeof(canonical_payload))) goto fail;

    char protected[TEXT_MAX];
    result = snprintf(protected, sizeof(protected),
                      "{\"alg\":\"EdDSA\",\"kid\":\"%s\",\"payload\":%s}",
                      command->kid, canonical_payload);
    if (!snprintf_ok(result, sizeof(protected))) goto fail;
    char canonical_frame[FRAME_MAX];
    result = snprintf(canonical_frame, sizeof(canonical_frame),
        "{\"alg\":\"EdDSA\",\"kid\":\"%s\",\"payload\":%s,\"signature\":\"%s\"}",
        command->kid, canonical_payload, signature_text);
    if (!snprintf_ok(result, sizeof(canonical_frame)) || strcmp(frame, canonical_frame) != 0) goto fail;

    uint8_t public_key[32], signature[64];
    if (!valid_kid(command->kid, public_key) || !b64url_decode(signature_text, signature, 64)) goto fail;
    size_t domain_size = sizeof(DOMAIN) - 1;
    size_t protected_size = strlen(protected);
    if (domain_size + protected_size > TEXT_MAX) goto fail;
    uint8_t signed_message[TEXT_MAX];
    memcpy(signed_message, DOMAIN, domain_size);
    memcpy(signed_message + domain_size, protected, protected_size);
    bool valid = crypto_ed25519_check(signature, public_key, signed_message,
                                      domain_size + protected_size) == 0;
    crypto_wipe(public_key, sizeof(public_key));
    crypto_wipe(signature, sizeof(signature));
    crypto_wipe(signed_message, domain_size + protected_size);
    cJSON_Delete(root);
    return valid;
fail:
    if (root != NULL) cJSON_Delete(root);
    return false;
}

static bool actuate(const char *position) {
    ledc_timer_config_t timer = {
        .speed_mode = LEDC_LOW_SPEED_MODE,
        .duty_resolution = LEDC_TIMER_13_BIT,
        .timer_num = LEDC_TIMER_0,
        .freq_hz = 50,
        .clk_cfg = LEDC_AUTO_CLK,
    };
    ledc_channel_config_t channel = {
        .gpio_num = SERVO_GPIO,
        .speed_mode = LEDC_LOW_SPEED_MODE,
        .channel = LEDC_CHANNEL_0,
        .intr_type = LEDC_INTR_DISABLE,
        .timer_sel = LEDC_TIMER_0,
        .duty = 0,
        .hpoint = 0,
    };
    if (ledc_timer_config(&timer) != ESP_OK || ledc_channel_config(&channel) != ESP_OK) return false;
    uint32_t pulse = strcmp(position, "open") == 0 ? SERVO_OPEN_US : SERVO_CLOSED_US;
    uint32_t duty = (pulse * ((1U << 13) - 1U)) / SERVO_PERIOD_US;
    bool ok = ledc_set_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, duty) == ESP_OK &&
              ledc_update_duty(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0) == ESP_OK;
    vTaskDelay(pdMS_TO_TICKS(SERVO_HOLD_MS));
    ledc_stop(LEDC_LOW_SPEED_MODE, LEDC_CHANNEL_0, 0);
    gpio_reset_pin(SERVO_GPIO);
    gpio_set_direction(SERVO_GPIO, GPIO_MODE_INPUT);
    return ok;
}

static bool emit_ack(const device_state_t *state, const command_t *command, bool succeeded) {
    const char *result_text = succeeded ? "succeeded" : "failed";
    char unsigned_payload[TEXT_MAX];
    int result = snprintf(unsigned_payload, sizeof(unsigned_payload),
        "{\"actuator_count\":%lu,\"boot_counter\":%lu,\"capability_id\":\"%s\","
        "\"command_id\":\"%s\",\"device\":\"%s\",\"device_id\":\"%s\","
        "\"profile\":\"%s\",\"result\":\"%s\",\"sequence\":%lu,\"type\":\"%s\"}",
        (unsigned long)state->actuator_count, (unsigned long)state->boot_counter,
        command->capability_id, command->command_id, state->device_kid, state->device_id,
        PROFILE, result_text, (unsigned long)command->sequence, ACK_TYPE);
    if (!snprintf_ok(result, sizeof(unsigned_payload))) return false;
    char ack_hash[65];
    sha256_hex((const uint8_t *)unsigned_payload, strlen(unsigned_payload), ack_hash);
    char ack_id[96];
    result = snprintf(ack_id, sizeof(ack_id), "kinegrant:device-ack:%s", ack_hash);
    if (!snprintf_ok(result, sizeof(ack_id))) return false;
    char payload[TEXT_MAX];
    result = snprintf(payload, sizeof(payload),
        "{\"ack_id\":\"%s\",\"actuator_count\":%lu,\"boot_counter\":%lu,"
        "\"capability_id\":\"%s\",\"command_id\":\"%s\",\"device\":\"%s\","
        "\"device_id\":\"%s\",\"profile\":\"%s\",\"result\":\"%s\",\"sequence\":%lu,\"type\":\"%s\"}",
        ack_id, (unsigned long)state->actuator_count, (unsigned long)state->boot_counter,
        command->capability_id, command->command_id, state->device_kid, state->device_id,
        PROFILE, result_text, (unsigned long)command->sequence, ACK_TYPE);
    if (!snprintf_ok(result, sizeof(payload))) return false;
    char protected[TEXT_MAX];
    result = snprintf(protected, sizeof(protected),
                      "{\"alg\":\"EdDSA\",\"kid\":\"%s\",\"payload\":%s}",
                      state->device_kid, payload);
    if (!snprintf_ok(result, sizeof(protected))) return false;
    size_t domain_size = sizeof(DOMAIN) - 1;
    size_t protected_size = strlen(protected);
    uint8_t signed_message[TEXT_MAX];
    if (domain_size + protected_size > sizeof(signed_message)) return false;
    memcpy(signed_message, DOMAIN, domain_size);
    memcpy(signed_message + domain_size, protected, protected_size);
    uint8_t signature[64];
    crypto_ed25519_sign(signature, state->device_secret, signed_message,
                        domain_size + protected_size);
    char signature_text[87];
    bool ok = b64url_encode(signature, sizeof(signature), signature_text,
                            sizeof(signature_text));
    crypto_wipe(signature, sizeof(signature));
    crypto_wipe(signed_message, domain_size + protected_size);
    if (!ok) return false;
    printf("{\"alg\":\"EdDSA\",\"kid\":\"%s\",\"payload\":%s,\"signature\":\"%s\"}\n",
           state->device_kid, payload, signature_text);
    return true;
}

static void lock_forever(device_state_t *state) {
    gpio_reset_pin(SERVO_GPIO);
    gpio_set_direction(SERVO_GPIO, GPIO_MODE_INPUT);
    crypto_wipe(state->device_secret, sizeof(state->device_secret));
    for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

void app_main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    device_state_t state = {0};
    gpio_reset_pin(SERVO_GPIO);
    gpio_set_direction(SERVO_GPIO, GPIO_MODE_INPUT);
    if (nvs_flash_init() != ESP_OK || !load_config(&state) || !begin_boot(&state)) {
        lock_forever(&state);
    }
    char frame[FRAME_MAX];
    for (;;) {
        if (!new_challenge(&state)) lock_forever(&state);
        if (!read_frame(frame)) continue;
        command_t command = {0};
        int64_t elapsed = esp_timer_get_time() - state.challenge_issued_us;
        bool authorized = elapsed >= 0 && elapsed < CHALLENGE_US &&
                          verify_command(frame, &state, &command);
        state.challenge_nonce[0] = '\0';
        if (!authorized || !persist_consumption(&state, &command)) continue;
        bool succeeded = actuate(command.position);
        if (!emit_ack(&state, &command, succeeded)) lock_forever(&state);
    }
}
