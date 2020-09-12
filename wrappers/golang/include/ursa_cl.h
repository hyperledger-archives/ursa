#include <stdint.h>

typedef enum {
    SUCCESS = 0,
    GENERAL_ERROR = 1,
} ursa_error_t;

ursa_error_t ursa_cl_new_nonce(void** nonce_p);
ursa_error_t ursa_cl_nonce_to_json(void* nonce, const char** nonce_json_p);
