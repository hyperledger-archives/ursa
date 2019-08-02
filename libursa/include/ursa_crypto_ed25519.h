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

extern int32_t ursa_ed25519_keypair_from_seed(const struct ByteBuffer* const seed,
                                              const struct ByteBuffer* public_key,
                                              const struct ByteBuffer* private_key,
                                              const struct ExternError* err);

extern int32_t ursa_ed25519_get_public_key(const struct ByteBuffer* const private_key,
                                           const struct ByteBuffer* public_key,
                                           const struct ExternError* err);

extern int32_t ursa_ed25519_sign(const struct ByteBuffer* const message,
                                 const struct ByteBuffer* const private_key,
                                 const struct ByteBuffer* signature,
                                 const struct ExternError* err);

extern int32_t ursa_ed25519_verify(const struct ByteBuffer* const message,
                                   const struct ByteBuffer* const signature,
                                   const struct ByteBuffer* const public_key,
                                   const struct ExternError* err);
#ifdef __cplusplus
}
#endif

#endif
