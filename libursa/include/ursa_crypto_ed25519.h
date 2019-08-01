#ifndef __ursa__crypto__ed25519__included__
#define __ursa__crypto__ed25519__included__

#ifdef __cplusplus
extern "C" {
#endif

extern void ursa_ed25519_bytebuffer_free(struct ByteBuffer buffer);
extern void ursa_ed25519_string_free(char *s);

extern int32_t ursa_ed25519_get_public_key_size(void);
extern int32_t ursa_ed25519_get_private_key_size(void);
extern int32_t ursa_ed25519_get_signature_size(void);

extern int32_t ursa_ed25519_keypair_new(const struct ByteBuffer* public_key,
                                        const struct ByteBuffer* private_key,
                                        const struct ExternError* err);

extern int32_t ursa_ed25519_keypair_from_seed(const uint8_t* const seed, uint64_t seed_len,
                                              const struct ByteBuffer* public_key,
                                              const struct ByteBuffer* private_key,
                                              const struct ExternError* err);

extern int32_t ursa_ed25519_get_public_key(const uint8_t* const private_key, uint64_t private_key_len,
                                           const struct ByteBuffer* public_key,
                                           const struct ExternError* err);

extern int32_t ursa_ed25519_sign(const uint8_t* const message, uint64_t message_len,
                                 const uint8_t* const private_key, uint64_t private_key_len,
                                 const struct ByteBuffer* signature,
                                 const struct ExternError* err);

extern int32_t ursa_ed25519_verify(const uint8_t* const message, uint64_t message_len,
                                   const uint8_t* const signature, uint64_t signature_len,
                                   const uint8_t* const public_key, uint64_t public_key_len,
                                   const struct ExternError* err);
#ifdef __cplusplus
}
#endif

#endif
