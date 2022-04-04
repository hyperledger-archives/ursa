#ifndef __ursa__crypto__encryption__included__
#define __ursa__crypto__encryption__included__

#ifdef __cplusplus
extern "C" {
#endif

extern int32_t ursa_aes128_cbc_hmac256_keysize(void);
extern int32_t ursa_aes128_cbc_hmac256_noncesize(void);
extern int32_t ursa_aes128_cbc_hmac256_tagsize(void);
extern int32_t ursa_aes256_cbc_hmac512_keysize(void);
extern int32_t ursa_aes256_cbc_hmac512_noncesize(void);
extern int32_t ursa_aes256_cbc_hmac512_tagsize(void);
extern int32_t ursa_aes128_gcm_keysize(void);
extern int32_t ursa_aes128_gcm_noncesize(void);
extern int32_t ursa_aes128_gcm_tagsize(void);
extern int32_t ursa_aes256_gcm_keysize(void);
extern int32_t ursa_aes256_gcm_noncesize(void);
extern int32_t ursa_aes256_gcm_tagsize(void);
extern int32_t ursa_xchacha20_poly1305_keysize(void);
extern int32_t ursa_xchacha20_poly1305_noncesize(void);
extern int32_t ursa_xchacha20_poly1305_tagsize(void);
extern int32_t random_bytes(uint32_t bytes);

extern int32_t ursa_encrypt(const struct ByteBuffer* ciphertext,
                            const char* const algorithm,
                            const struct ByteBuffer* const key,
                            const struct ByteBuffer* const nonce,
                            const struct ByteBuffer* const aad,
                            const struct ByteBuffer* const plaintext,
                            const struct ExternError* err);
extern int32_t ursa_decrypt(const struct ByteBuffer* plaintext,
                            const char* const algorithm,
                            const struct ByteBuffer* const key,
                            const struct ByteBuffer* const nonce,
                            const struct ByteBuffer* const aad,
                            const struct ByteBuffer* const ciphertext,
                            const struct ExternError* err);

extern int32_t ursa_aes128_cbc_hmac256_encrypt(const struct ByteBuffer* ciphertext,
                                               const struct ByteBuffer* const key,
                                               const struct ByteBuffer* const nonce,
                                               const struct ByteBuffer* const aad,
                                               const struct ByteBuffer* const plaintext,
                                               const struct ExternError* err);
extern int32_t ursa_aes128_cbc_hmac256_decrypt(const struct ByteBuffer* plaintext,
                                               const struct ByteBuffer* const key,
                                               const struct ByteBuffer* const nonce,
                                               const struct ByteBuffer* const aad,
                                               const struct ByteBuffer* const ciphertext,
                                               const struct ExternError* err);

extern int32_t ursa_aes256_cbc_hmac512_encrypt(const struct ByteBuffer* ciphertext,
                                               const struct ByteBuffer* const key,
                                               const struct ByteBuffer* const nonce,
                                               const struct ByteBuffer* const aad,
                                               const struct ByteBuffer* const plaintext,
                                               const struct ExternError* err);
extern int32_t ursa_aes256_cbc_hmac512_decrypt(const struct ByteBuffer* plaintext,
                                               const struct ByteBuffer* const key,
                                               const struct ByteBuffer* const nonce,
                                               const struct ByteBuffer* const aad,
                                               const struct ByteBuffer* const ciphertext,
                                               const struct ExternError* err);

extern int32_t ursa_aes128_gcm_encrypt(const struct ByteBuffer* ciphertext,
                                       const struct ByteBuffer* const key,
                                       const struct ByteBuffer* const nonce,
                                       const struct ByteBuffer* const aad,
                                       const struct ByteBuffer* const plaintext,
                                       const struct ExternError* err);
extern int32_t ursa_aes128_gcm_decrypt(const struct ByteBuffer* plaintext,
                                       const struct ByteBuffer* const key,
                                       const struct ByteBuffer* const nonce,
                                       const struct ByteBuffer* const aad,
                                       const struct ByteBuffer* const ciphertext,
                                       const struct ExternError* err);

extern int32_t ursa_aes256_gcm_encrypt(const struct ByteBuffer* ciphertext,
                                       const struct ByteBuffer* const key,
                                       const struct ByteBuffer* const nonce,
                                       const struct ByteBuffer* const aad,
                                       const struct ByteBuffer* const plaintext,
                                       const struct ExternError* err);
extern int32_t ursa_aes256_gcm_decrypt(const struct ByteBuffer* plaintext,
                                       const struct ByteBuffer* const key,
                                       const struct ByteBuffer* const nonce,
                                       const struct ByteBuffer* const aad,
                                       const struct ByteBuffer* const ciphertext,
                                       const struct ExternError* err);

extern int32_t ursa_xchacha20_poly1305_encrypt(const struct ByteBuffer* ciphertext,
                                               const struct ByteBuffer* const key,
                                               const struct ByteBuffer* const nonce,
                                               const struct ByteBuffer* const aad,
                                               const struct ByteBuffer* const plaintext,
                                               const struct ExternError* err);
extern int32_t ursa_xchacha20_poly1305_decrypt(const struct ByteBuffer* plaintext,
                                               const struct ByteBuffer* const key,
                                               const struct ByteBuffer* const nonce,
                                               const struct ByteBuffer* const aad,
                                               const struct ByteBuffer* const ciphertext,
                                               const struct ExternError* err);


#ifdef __cplusplus
}
#endif

#endif
