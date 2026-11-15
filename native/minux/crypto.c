/* Copyright 2026 Nils Kopal. Apache-2.0. Mbed TLS crypto provider for MinUX. */
#include <errno.h>
#include <fcntl.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

void mlc_explicit_bzero(void *, size_t);

static const mbedtls_md_info_t *digest(int algorithm) {
  return mbedtls_md_info_from_type(algorithm == 256   ? MBEDTLS_MD_SHA256
                                   : algorithm == 384 ? MBEDTLS_MD_SHA384
                                                      : MBEDTLS_MD_NONE);
}
static int entropy(void *context, unsigned char *output, size_t length) {
  size_t done = 0;
  int fd = open("/dev/urandom", O_RDONLY);
  (void)context;
  if (fd < 0)
    return -1;
  while (done < length) {
    ssize_t actual = read(fd, output + done, length - done);
    if (actual < 0 && errno == EINTR)
      continue;
    if (actual <= 0 || (size_t)actual > length - done) {
      close(fd);
      return -1;
    }
    done += actual;
  }
  return close(fd);
}
int mlc_crypto_random(unsigned char *output, size_t length) {
  int result = entropy(0, output, length);
  if (result)
    mlc_explicit_bzero(output, length);
  return result == 0;
}
int mlc_crypto_hash(int algorithm, const unsigned char *key, int64_t key_length,
                    const unsigned char *input, size_t length,
                    unsigned char *output) {
  const mbedtls_md_info_t *info = digest(algorithm);
  int result = -1;
  if (info)
    result = key_length < 0 ? mbedtls_md(info, input, length, output)
                            : mbedtls_md_hmac(info, key, (size_t)key_length,
                                              input, length, output);
  if (result && info)
    mlc_explicit_bzero(output, mbedtls_md_get_size(info));
  return result == 0;
}
int mlc_crypto_pbkdf2(int algorithm, const unsigned char *password,
                      size_t password_length, const unsigned char *salt,
                      size_t salt_length, int iterations, unsigned char *output,
                      uint32_t length) {
  const mbedtls_md_info_t *info = digest(algorithm);
  mbedtls_md_context_t context;
  int result = -1;
  mbedtls_md_init(&context);
  if (info && iterations > 0 && !mbedtls_md_setup(&context, info, 1))
    result = mbedtls_pkcs5_pbkdf2_hmac(
        &context, password, password_length, salt, salt_length,
        (unsigned int)iterations, length, output);
  mbedtls_md_free(&context);
  if (result)
    mlc_explicit_bzero(output, length);
  return result == 0;
}
int mlc_crypto_hkdf(int algorithm, const unsigned char *input,
                    size_t input_length, const unsigned char *salt,
                    size_t salt_length, const unsigned char *info,
                    size_t info_length, unsigned char *output, size_t length) {
  const mbedtls_md_info_t *md = digest(algorithm);
  int result = md ? mbedtls_hkdf(md, salt, salt_length, input, input_length,
                                 info, info_length, output, length)
                  : -1;
  if (result)
    mlc_explicit_bzero(output, length);
  return result == 0;
}
int mlc_crypto_gcm(int encrypting, const unsigned char *key,
                   const unsigned char *nonce, const unsigned char *aad,
                   size_t aad_length, const unsigned char *input,
                   size_t input_length, unsigned char *output,
                   size_t tag_length) {
  mbedtls_gcm_context context;
  int result = -1;
  size_t payload = encrypting                   ? input_length
                   : input_length >= tag_length ? input_length - tag_length
                                                : 0;
  size_t output_length = encrypting ? input_length + tag_length : payload;
  mbedtls_gcm_init(&context);
  if (tag_length >= 12 && tag_length <= 16 &&
      (encrypting || input_length >= tag_length) &&
      !mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256)) {
    if (encrypting)
      result = mbedtls_gcm_crypt_and_tag(&context, MBEDTLS_GCM_ENCRYPT, payload,
                                         nonce, 12, aad, aad_length, input,
                                         output, tag_length, output + payload);
    else
      result = mbedtls_gcm_auth_decrypt(&context, payload, nonce, 12, aad,
                                        aad_length, input + payload, tag_length,
                                        input, output);
  }
  mbedtls_gcm_free(&context);
  if (result)
    mlc_explicit_bzero(output, output_length);
  return result == 0;
}
/* RFC 7748 little-endian keys, with the required scalar clamping and input
 * masking. Mbed TLS performs the multiplication and rejects low-order peers. */
int mlc_crypto_x25519(const unsigned char *private_key,
                      const unsigned char *public_key, unsigned char *output) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point peer, product;
  mbedtls_mpi scalar;
  unsigned char secret[32], encoded[32];
  int result;
  memcpy(secret, private_key, 32);
  secret[0] &= 248;
  secret[31] &= 127;
  secret[31] |= 64;
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&peer);
  mbedtls_ecp_point_init(&product);
  mbedtls_mpi_init(&scalar);
  result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_CURVE25519);
  if (!result)
    result = mbedtls_mpi_read_binary_le(&scalar, secret, 32);
  if (!result && public_key) {
    memcpy(encoded, public_key, 32);
    encoded[31] &= 127;
    result = mbedtls_ecp_point_read_binary(&group, &peer, encoded, 32);
  } else if (!result)
    result = mbedtls_ecp_copy(&peer, &group.G);
  if (!result)
    result = mbedtls_ecp_mul(&group, &product, &scalar, &peer, entropy, 0);
  if (!result && mbedtls_mpi_cmp_int(&product.MBEDTLS_PRIVATE(X), 0) == 0)
    result = -1;
  if (!result)
    result =
        mbedtls_mpi_write_binary_le(&product.MBEDTLS_PRIVATE(X), output, 32);
  if (result)
    mlc_explicit_bzero(output, 32);
  mlc_explicit_bzero(secret, sizeof(secret));
  mlc_explicit_bzero(encoded, sizeof(encoded));
  mbedtls_mpi_free(&scalar);
  mbedtls_ecp_point_free(&product);
  mbedtls_ecp_point_free(&peer);
  mbedtls_ecp_group_free(&group);
  return result == 0;
}
int mlc_crypto_p256_verify(const unsigned char *public_key,
                           const unsigned char *hash,
                           const unsigned char *signature) {
  mbedtls_ecp_group group;
  mbedtls_ecp_point point;
  mbedtls_mpi r, s;
  unsigned char encoded[65];
  int result;
  encoded[0] = 4;
  memcpy(encoded + 1, public_key, 64);
  mbedtls_ecp_group_init(&group);
  mbedtls_ecp_point_init(&point);
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  result = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1);
  if (!result)
    result =
        mbedtls_ecp_point_read_binary(&group, &point, encoded, sizeof(encoded));
  if (!result)
    result = mbedtls_ecp_check_pubkey(&group, &point);
  if (!result)
    result = mbedtls_mpi_read_binary(&r, signature, 32);
  if (!result)
    result = mbedtls_mpi_read_binary(&s, signature + 32, 32);
  if (!result)
    result = mbedtls_ecdsa_verify(&group, hash, 32, &point, &r, &s);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  mbedtls_ecp_point_free(&point);
  mbedtls_ecp_group_free(&group);
  return result == 0;
}
