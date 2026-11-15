/* Copyright 2026 Nils Kopal. Apache-2.0. Mbed TLS transport for native MinUX.
 */
#include <errno.h>
#include <fcntl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

void mlc_explicit_bzero(void *, size_t);
static pthread_once_t psa_once = PTHREAD_ONCE_INIT;
static psa_status_t psa_status = PSA_ERROR_BAD_STATE;
static void initialize_psa(void) { psa_status = psa_crypto_init(); }

typedef struct {
  mbedtls_ssl_context ssl;
  mbedtls_ssl_config config;
  mbedtls_ctr_drbg_context random;
  mbedtls_x509_crt trust, certificate;
  mbedtls_pk_context key;
  int socket, last_error, closed;
} MinuxTls;

static int entropy(void *ignored, unsigned char *output, size_t length) {
  int fd = open("/dev/urandom", O_RDONLY);
  size_t done = 0;
  (void)ignored;
  if (fd < 0)
    return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
  while (done < length) {
    ssize_t n = read(fd, output + done, length - done);
    if (n <= 0 || (size_t)n > length - done) {
      close(fd);
      return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
    }
    done += (size_t)n;
  }
  return close(fd) == 0 ? 0 : MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
}

static int send_record(void *context, const unsigned char *data,
                       size_t length) {
  MinuxTls *state = context;
  ssize_t n = send(state->socket, data, length, 0);
  if (n >= 0)
    return (int)n;
  return errno == EAGAIN || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_WRITE
                                           : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
static int receive_record(void *context, unsigned char *data, size_t length) {
  MinuxTls *state = context;
  ssize_t n = recv(state->socket, data, length, 0);
  if (n >= 0)
    return (int)n;
  return errno == EAGAIN || errno == EINTR ? MBEDTLS_ERR_SSL_WANT_READ
                                           : MBEDTLS_ERR_SSL_INTERNAL_ERROR;
}
void mlt_close(void *context) {
  MinuxTls *state = context;
  if (!state)
    return;
  mbedtls_ssl_free(&state->ssl);
  mbedtls_ssl_config_free(&state->config);
  mbedtls_x509_crt_free(&state->trust);
  mbedtls_x509_crt_free(&state->certificate);
  mbedtls_pk_free(&state->key);
  mbedtls_ctr_drbg_free(&state->random);
  mlc_explicit_bzero(state, sizeof(*state));
  free(state);
}
static MinuxTls *create(int socket, int server, int minimum) {
  MinuxTls *state = calloc(1, sizeof(*state));
  int result;
  if (!state || (minimum != 12 && minimum != 13)) {
    free(state);
    return 0;
  }
  state->socket = socket;
  mbedtls_ssl_init(&state->ssl);
  mbedtls_ssl_config_init(&state->config);
  mbedtls_ctr_drbg_init(&state->random);
  mbedtls_x509_crt_init(&state->trust);
  mbedtls_x509_crt_init(&state->certificate);
  mbedtls_pk_init(&state->key);
  if (pthread_once(&psa_once, initialize_psa) || psa_status != PSA_SUCCESS) {
    mlt_close(state);
    return 0;
  }
  result = mbedtls_ctr_drbg_seed(&state->random, entropy, 0,
                                 (const unsigned char *)"MiniLang-MinUX", 14);
  if (result) {
    mlt_close(state);
    return 0;
  }
  result = mbedtls_ssl_config_defaults(
      &state->config, server ? MBEDTLS_SSL_IS_SERVER : MBEDTLS_SSL_IS_CLIENT,
      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
  if (result) {
    mlt_close(state);
    return 0;
  }
  mbedtls_ssl_conf_min_tls_version(&state->config,
                                   minimum == 13 ? MBEDTLS_SSL_VERSION_TLS1_3
                                                 : MBEDTLS_SSL_VERSION_TLS1_2);
  mbedtls_ssl_conf_rng(&state->config, mbedtls_ctr_drbg_random, &state->random);
  return state;
}
static int setup(MinuxTls *state) {
  int result = mbedtls_ssl_setup(&state->ssl, &state->config);
  if (result)
    return result;
  mbedtls_ssl_set_bio(&state->ssl, state, send_record, receive_record, 0);
  return 0;
}

void *mlt_client(int socket, const char *hostname, int verify,
                 const unsigned char *pin, int pin_length, int minimum,
                 const char *ca_file) {
  MinuxTls *state;
  int result;
  if (!hostname || !*hostname || (pin_length != 0 && pin_length != 32) ||
      (pin_length && (!pin || !verify)))
    return 0;
  state = create(socket, 0, minimum);
  if (!state)
    return 0;
  if (verify && !pin_length) {
    result = mbedtls_x509_crt_parse_file(
        &state->trust,
        ca_file && *ca_file ? ca_file : "/etc/ssl/certs/ca-certificates.crt");
    if (result < 0) {
      mlt_close(state);
      return 0;
    }
    mbedtls_ssl_conf_ca_chain(&state->config, &state->trust, 0);
    mbedtls_ssl_conf_authmode(&state->config, MBEDTLS_SSL_VERIFY_REQUIRED);
  } else
    mbedtls_ssl_conf_authmode(&state->config, verify
                                                  ? MBEDTLS_SSL_VERIFY_OPTIONAL
                                                  : MBEDTLS_SSL_VERIFY_NONE);
  if (setup(state) || mbedtls_ssl_set_hostname(&state->ssl, hostname)) {
    mlt_close(state);
    return 0;
  }
  result = mbedtls_ssl_handshake(&state->ssl);
  if (result) {
    mlt_close(state);
    return 0;
  }
  if (pin_length) {
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&state->ssl);
    unsigned char digest[32];
    unsigned int difference = 0;
    size_t i;
    uint32_t flags = mbedtls_ssl_get_verify_result(&state->ssl);
    if (!peer || (flags & ~MBEDTLS_X509_BADCERT_NOT_TRUSTED) ||
        mbedtls_sha256(peer->raw.p, peer->raw.len, digest, 0)) {
      mlt_close(state);
      return 0;
    }
    for (i = 0; i < 32; i++)
      difference |= digest[i] ^ pin[i];
    mlc_explicit_bzero(digest, sizeof(digest));
    if (difference) {
      mlt_close(state);
      return 0;
    }
  }
  return state;
}

void *mlt_server(int socket, const char *certificate, const char *key,
                 int minimum, int require_client) {
  MinuxTls *state;
  if (!certificate || !key)
    return 0;
  state = create(socket, 1, minimum);
  if (!state)
    return 0;
  if (mbedtls_x509_crt_parse_file(&state->certificate, certificate) ||
      mbedtls_pk_parse_keyfile(&state->key, key, 0, mbedtls_ctr_drbg_random,
                               &state->random) ||
      mbedtls_ssl_conf_own_cert(&state->config, &state->certificate,
                                &state->key)) {
    mlt_close(state);
    return 0;
  }
  if (require_client) {
    if (mbedtls_x509_crt_parse_file(&state->trust,
                                    "/etc/ssl/certs/ca-certificates.crt") < 0) {
      mlt_close(state);
      return 0;
    }
    mbedtls_ssl_conf_ca_chain(&state->config, &state->trust, 0);
  }
  mbedtls_ssl_conf_authmode(&state->config, require_client
                                                ? MBEDTLS_SSL_VERIFY_REQUIRED
                                                : MBEDTLS_SSL_VERIFY_NONE);
  if (setup(state) || mbedtls_ssl_handshake(&state->ssl)) {
    mlt_close(state);
    return 0;
  }
  return state;
}
int mlt_write(void *context, const unsigned char *data, size_t length) {
  MinuxTls *state = context;
  if (!state || state->closed || (!data && length))
    return -1;
  if (length > MBEDTLS_SSL_OUT_CONTENT_LEN)
    length = MBEDTLS_SSL_OUT_CONTENT_LEN;
  int result = mbedtls_ssl_write(&state->ssl, data, length);
  state->last_error = result < 0 ? result : 0;
  return result;
}
int mlt_read(void *context, unsigned char *data, size_t length) {
  MinuxTls *state = context;
  if (!state || state->closed || (!data && length))
    return -1;
  int result = mbedtls_ssl_read(&state->ssl, data, length);
  if (result == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
    return 0;
  state->last_error = result < 0 ? result : 0;
  return result;
}
int mlt_shutdown(void *context) {
  MinuxTls *state = context;
  if (!state || state->closed)
    return 0;
  int result = mbedtls_ssl_close_notify(&state->ssl);
  if (!result)
    state->closed = 1;
  state->last_error = result;
  return result;
}
int mlt_error(void *context, char *output, size_t size) {
  MinuxTls *state = context;
  if (!output || !size)
    return -1;
  mbedtls_strerror(state ? state->last_error : MBEDTLS_ERR_SSL_INTERNAL_ERROR,
                   output, size);
  output[size - 1] = 0;
  return 0;
}
