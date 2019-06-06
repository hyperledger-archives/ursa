#ifndef __ursa__crypto__included__
#define __ursa__crypto__included__

#include <stdint.h>

typedef enum {
    SUCCESS = 0,
    KEYPAIR_ERROR = 1,
    SIGNING_ERROR = 2,
    VERIFY_ERROR = 3
} ursa_ed25519_t;

struct ByteBuffer {
    int64_t len;
    uint8_t *data;
};

struct ExternError {
    ursa_ed25519_t code;
    char* message; /* note: nullable */
};

#include "ursa_crypto_ed25519.h"

#endif
