#ifndef __ursa__crypto__included__
#define __ursa__crypto__included__

#include <stdint.h>

typedef enum {
    SUCCESS = 0,
    KEYPAIR_ERROR = 1,
    SIGNING_ERROR = 2,
    VERIFY_ERROR = 3,
    INVALID_PARAM1 = 4,
    INVALID_PARAM2 = 5,
    ENCRYPTION_ERROR = 6,
    DECRYPTION_ERROR = 7,
    INVALID_KEY_LENGTH = 8,
    INVALID_NONCE_LENGTH = 9,
    RANDOM_BYTES_ERROR = 10,
    INVALID_CIPHER = 11,
} ursa_error_t;

struct ByteBuffer {
    int64_t len;
    uint8_t *data;
};

struct ExternError {
    ursa_error_t code;
    char* message; /* note: nullable */
};

extern void ursa_bytebuffer_free(struct ByteBuffer buffer);
extern void ursa_string_free(char *s);

#include "ursa_crypto_ed25519.h"
#include "ursa_crypto_encryption.h"

#endif
