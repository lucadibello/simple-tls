#include "tls_impl.h"
#include "tls_connection.h"
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>

struct tls_version tls_1_2 = {.major = 3, .minor = 3};

// This function is used to convert a number is a list of bytes encoded in
// big-endian
void num_to_bytes(uint64_t in, uint8_t *out, int count) {
  for (int i = count - 1; i >= 0; i--) {
    out[i] = in & 0xff;
    in >>= 8;
  }
}

void tls_record_free(struct tls_record *record) { free(record->fragment); }

struct tls_context *tls_context_new(struct tls_connection *conn) {
  EVP_MD_CTX *hashing = EVP_MD_CTX_new();
  if (!hashing)
    return NULL;

  if (!EVP_DigestInit(hashing, EVP_sha256())) {
    EVP_MD_CTX_destroy(hashing);
    return NULL;
  }

  struct tls_context *ctx = malloc(sizeof(struct tls_context));
  if (!ctx) {
    EVP_MD_CTX_destroy(hashing);
    return NULL;
  }
  ctx->version = tls_1_2;
  ctx->connection = conn;
  ctx->handshake_hashing = hashing;
  ctx->client_seq = 0;
  ctx->server_seq = 0;
  return ctx;
}

void tls_context_free(struct tls_context *ctx) {
  EVP_MD_CTX_free(ctx->handshake_hashing);
  free(ctx);
}

int tls_context_send_record(const struct tls_context *ctx, ...) {
  uint8_t *buf;
  size_t buf_len = 0;
  const struct tls_record *arg;
  va_list ap;

  va_start(ap, ctx);
  while ((arg = va_arg(ap, const struct tls_record *)))
    buf_len += 5 + arg->length;
  va_end(ap);

  if (buf_len == 0)
    return 0;

  buf = malloc(buf_len);
  if (!buf)
    return 0;

  uint8_t *p = buf;

  va_start(ap, ctx);
  while ((arg = va_arg(ap, const struct tls_record *))) {
    *p++ = arg->type;
    *p++ = arg->version.major;
    *p++ = arg->version.minor;
    num_to_bytes(arg->length, p, 2);
    p += 2;
    memcpy(p, arg->fragment, arg->length);
    p += arg->length;
  }
  va_end(ap);

  int ret = tls_connection_write(ctx->connection, buf, buf_len) < 0 ? 0 : 1;
  free(buf);
  return ret;
}

int tls_context_recv_record(const struct tls_context *ctx,
                            struct tls_record *record) {
  uint8_t header[5];

  if (tls_connection_read(ctx->connection, header, 5) < 0)
    return 0;

  record->type = header[0];
  record->version.major = header[1];
  record->version.minor = header[2];
  record->length = (header[3] << 8) + header[4];
  if (!(record->fragment = malloc(record->length)))
    return 0;

  if (tls_connection_read(ctx->connection, record->fragment, record->length) <
      0) {
    free(record->fragment);
    return 0;
  }

  return 1;
}

int tls_context_hash_handshake(const struct tls_context *ctx,
                               const uint8_t *handshake, size_t len) {

  return EVP_DigestUpdate(ctx->handshake_hashing, handshake, len);
}

int tls_context_handshake_digest(struct tls_context *ctx, uint8_t *out) {
  if (!out)
    return SHA256_DIGEST_LENGTH;

  EVP_MD_CTX *ctx_copy = EVP_MD_CTX_new();

  if (!ctx_copy)
    return 0;

  if (EVP_MD_CTX_copy(ctx_copy, ctx->handshake_hashing) != 1 ||
      EVP_DigestFinal(ctx_copy, out, NULL) != 1) {
    EVP_MD_CTX_free(ctx_copy);
    return 0;
  }

  EVP_MD_CTX_free(ctx_copy);
  return SHA256_DIGEST_LENGTH;
}

int tls_context_derive_keys(struct tls_context *ctx,
                            const struct rsa_premaster_secret *premaster) {
  // Serialize the RSA premaster secret: we write in a buffer the minor/major
  // version and the actual secret
  uint8_t premaster_secret[48];
  premaster_secret[0] = premaster->version.major;
  premaster_secret[1] = premaster->version.minor;
  memcpy(premaster_secret + 2, premaster->random, 46);

  // Compute the ctx->master_secret by using the PRF function as described
  // in the notes
  uint8_t master_key_secret[77]; // 13 (label) + 32 (client random) + 32 (server
                                 // random) = 77
  memcpy(master_key_secret, "master secret", 13);
  memcpy(master_key_secret + 13, ctx->client_random, 32);
  memcpy(master_key_secret + 45, ctx->server_random, 32);
  tls_prf(
      premaster_secret, sizeof(premaster_secret), // Premaster secret
      master_key_secret,
      sizeof(master_key_secret), // Seed = label + client_random + server_random
      ctx->master_secret, 48     // Where to store the output (master secret)
  );

  uint8_t key_block[96];

  // Compute the key_block using the PRF function as described in the notes
  uint8_t key_block_seed[77]; // 13 (label) + 32 (client random) + 32 (server
                              // random) = 77
  memcpy(key_block_seed, "key expansion", 13);
  memcpy(key_block_seed + 13, ctx->server_random, 32);
  memcpy(key_block_seed + 45, ctx->client_random, 32);
  tls_prf(
      ctx->master_secret, 48, // Computed master secret
      key_block_seed,
      sizeof(key_block_seed), // Seed = label + client_random + server_random
      key_block, sizeof(key_block) // Where to store the output (key block)
  );

  // Extract the keys from the key_block
  memcpy(ctx->client_mac_key, key_block, 32);
  memcpy(ctx->server_mac_key, key_block + 32, 32);
  memcpy(ctx->client_enc_key, key_block + 64, 16);
  memcpy(ctx->server_enc_key, key_block + 80, 16);

  // Return 1 if everything went well
  return 1;
}

size_t tls_context_encrypt(struct tls_context *ctx,
                           const struct tls_record *record, uint8_t *out) {
  int block_size = EVP_CIPHER_get_block_size(EVP_aes_128_cbc());
  uint8_t iv[block_size];

  // Compute the padding length
  // uint8_t padding_len = block_size - ((record->length + SHA256_DIGEST_LENGTH) % block_size);
  // padding_len = padding_len == 0 ? block_size : padding_len;
  uint8_t padding_len = (record->length + SHA256_DIGEST_LENGTH) % block_size;
  padding_len = padding_len ? 16 - padding_len : 16;

  // Compute the total length of the ciphertext
  size_t cipher_len = record->length + SHA256_DIGEST_LENGTH + padding_len;
  size_t total_len = block_size + cipher_len; // Include IV in the total length

  // Randomly generate 16 bytes of IV and write them in out in clear (if possible)
  RAND_bytes(iv, block_size);

  // If out == NULL just return the length of the ciphertext (including the IV)
  if (!out) {
    return total_len;
  } else {
    // Write the IV in the output buffer
    memcpy(out, iv, block_size);
  }

  EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
  if (!enc_ctx)
    return 0;

  // Initialize the encryption context with the client_enc_key and the IV
  if (EVP_EncryptInit(enc_ctx, EVP_aes_128_cbc(), ctx->client_enc_key, iv) != 1) {
    EVP_CIPHER_CTX_free(enc_ctx);
    return 0;
  }

  // This line disables padding, you should do the padding yourself
  EVP_CIPHER_CTX_set_padding(enc_ctx, 0);

  // NOTE: At the moment, the ciphertext is just the IV
  int len, out_len = block_size;
  // Encrypt the plaintext
  if (EVP_EncryptUpdate(enc_ctx, out + out_len, &len, record->fragment, record->length) != 1) {
    EVP_CIPHER_CTX_free(enc_ctx);
    return 0;
  }
  out_len += len;

  // Compute the HMAC code as described in the notes and encrypt it by using a second call to the EVP_EncryptUpdate function
  uint8_t hmac[SHA256_DIGEST_LENGTH];
  uint8_t hmac_data[record->length + 13];
 
  // Fill the hmac_data buffer with the necessary data
  num_to_bytes(ctx->client_seq, hmac_data, 8);
  hmac_data[8] = record->type;
  hmac_data[9] = ctx->version.major;
  hmac_data[10] = ctx->version.minor;
  num_to_bytes(record->length, hmac_data + 11, 2);
  memcpy(hmac_data + 13, record->fragment, record->length); // Copy the plaintext
  
  // Compute the actual HMAC code
  if (!HMAC(EVP_sha256(), ctx->client_mac_key, 32, hmac_data, sizeof(hmac_data), hmac, NULL)) {
    EVP_CIPHER_CTX_free(enc_ctx);
    return 0;
  }

  // Encrypt the HMAC code
  if (EVP_EncryptUpdate(enc_ctx, out + out_len, &len, hmac, SHA256_DIGEST_LENGTH) != 1) {
    EVP_CIPHER_CTX_free(enc_ctx);
    return 0;
  }
  out_len += len;

  // Compute the padding
  uint8_t padding[padding_len];
  memset(padding, padding_len - 1, padding_len);
  
  // Encrypt the padding
  if (EVP_EncryptUpdate(enc_ctx, out + out_len, &len, padding, padding_len) != 1) {
    EVP_CIPHER_CTX_free(enc_ctx);
    return 0;
  }
  out_len += len;

  // Finalize the encryption process
  if (EVP_EncryptFinal(enc_ctx, out + out_len, &len) != 1) {
    EVP_CIPHER_CTX_free(enc_ctx);
    return 0;
  }
  out_len += len;

  EVP_CIPHER_CTX_free(enc_ctx);

  // Return the total length of the ciphertext (including the IV)
  return total_len;
}

size_t tls_context_decrypt(struct tls_context *ctx, const struct tls_record *record, uint8_t *out) {
  int block_size = EVP_CIPHER_get_block_size(EVP_aes_128_cbc());
  EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();

  // The length of the ciphertext excluding the IV
  size_t cipher_len = record->length - block_size;

  if (!dec_ctx)
    return 0;
  
  // Initialize decryption context with the IV
  if (EVP_DecryptInit(dec_ctx, EVP_aes_128_cbc(), ctx->server_enc_key, record->fragment) != 1) {
    EVP_CIPHER_CTX_free(dec_ctx);
    return 0;
  }
  
  EVP_CIPHER_CTX_set_padding(dec_ctx, 0);

  // Decrypt the fragment
  int len;
  uint8_t plaintext[cipher_len + block_size];  // buffer size should consider padding
  if (EVP_DecryptUpdate(dec_ctx, plaintext, &len, record->fragment + block_size, cipher_len) != 1) {
    EVP_CIPHER_CTX_free(dec_ctx);
    return 0;
  }
  int plaintext_len = len;

  // Finalize the decryption process
  if (EVP_DecryptFinal(dec_ctx, plaintext + len, &len) != 1) {
    EVP_CIPHER_CTX_free(dec_ctx);
    return 0;
  }
  plaintext_len += len;

  EVP_CIPHER_CTX_free(dec_ctx);

  // Compute the padding length by looking at the last byte of the decrypted text
  uint8_t padding_len = plaintext[plaintext_len - 1] + 1;
  // If the padding length hsa a value greater than the block size, return 0
  // as the padding has is invalid 
  if (padding_len > block_size) {
    return 0;
  }

  // Remove the padding from the plaintext length
  plaintext_len -= padding_len;

  // Compute the expected HMAC code
  uint8_t expected_hmac[SHA256_DIGEST_LENGTH];
  uint8_t hmac_data[plaintext_len + 13 - SHA256_DIGEST_LENGTH];

  // Fill the hmac_data buffer with the necessary data
  num_to_bytes(ctx->server_seq, hmac_data, 8);
  hmac_data[8] = record->type;
  hmac_data[9] = record->version.major;
  hmac_data[10] = record->version.minor;
  num_to_bytes(plaintext_len - SHA256_DIGEST_LENGTH, hmac_data + 11, 2);
  memcpy(hmac_data + 13, plaintext, plaintext_len - SHA256_DIGEST_LENGTH);

  // Compute the actual HMAC code
  if (!HMAC(EVP_sha256(), ctx->server_mac_key, sizeof(ctx->server_mac_key), hmac_data, sizeof(hmac_data), expected_hmac, NULL)) {
    return 0;
  }

  // Compare the expected HMAC code with the one in the plaintext
  if (memcmp(expected_hmac, plaintext + plaintext_len - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH) != 0) {
    return 0;
  }

  // Copy the plaintext to the output buffer, excluding the padding and HMAC
  if (out)
    memcpy(out, plaintext, plaintext_len - SHA256_DIGEST_LENGTH);

  // Return the length of the plaintext
  return plaintext_len - SHA256_DIGEST_LENGTH;
}
void client_hello_init(struct client_hello *hello) {
  // Initialize the fields of a client hello message
  // You should support only the TLS_RSA_WITH_AES_128_CBC_SHA256
  // cipher suite and no compression.
  //
  // The client does not have to restore a previous session.

  // Set the version to TLS 1.2
  hello->version = tls_1_2;

  // Generate random bytes for the client random field
  hello->random.gmt_unix_time = time(NULL);
  for (int i = 0; i < 28; i++)
    hello->random.random_bytes[i] = rand() % 256;

  // Setup the session compression method
  hello->compression_method = 0x0; // No compression

  // Setup the session compression method
  hello->cipher_suite = 0x003C; // TLS_RSA_WITH_AES_128_CBC_SHA256 (0x003C)

  // Setup the supported signature algorithm
  hello->sig_algo = 0x0401; // SHA256 + RSA
}

size_t client_hello_marshall(const struct client_hello *hello, uint8_t *out) {
  int len = 55;
  if (!out)
    return len;

  // Write the handshake message identifier
  out[0] = 0x01;

  // Write the length of the handshake message:
  // NOTE: Total length of the message = length - handshake identifier - length field
  //                                   = 55 bytes - 1 byte - 3 bytes = 51 bytes
  //                                   = 0x33 in big-endian
  //                                   = 0x00 0x00 0x33 using three bytes
  out[1] = 0x00;
  out[2] = 0x00;
  out[3] = 0x33;

  // Write the protocol version
  out[4] = hello->version.major;
  out[5] = hello->version.minor;

  // Write the client timestamp (convert to network byte order)
  uint32_t gmt_unix_time = htonl(hello->random.gmt_unix_time);
  memcpy(out + 6, &gmt_unix_time, 4);

  // Write the client random bytes
  memcpy(out + 10, hello->random.random_bytes, 28);

  // Write the session id (0 as we do not want to restore a previous session)
  out[38] = 0;

  // Write the cipher suites length (0x0002 in big-endian)
  out[39] = 0x00;
  out[40] = 0x02;

  // Write the actual cipher suite (convert to network byte order)
  uint16_t cipher_suite = htons(hello->cipher_suite);
  memcpy(out + 41, &cipher_suite, 2);

  // Write the compression methods length (1 byte)
  out[43] = 0x01;

  // Write the actual compression method (0x00 for no compression)
  out[44] = hello->compression_method;

  // Write TLS extensions
  // Total length of extensions (2 bytes, 0x0008 in big-endian)
  uint16_t ext_len = htons(0x0008);
  memcpy(out + 45, &ext_len, 2);

  // Extension type: signature algorithms (2 bytes, 0x000d in big-endian)
  uint16_t ext_type = htons(0x000d);
  memcpy(out + 47, &ext_type, 2);

  // Length of the extension data (2 bytes, 0x0004 in big-endian)
  uint16_t ext_data_len = htons(0x0004);
  memcpy(out + 49, &ext_data_len, 2);

  // Length of the provided list of algorithms (2 bytes, 0x0002 in big-endian)
  uint16_t algo_list_len = htons(0x0002);
  memcpy(out + 51, &algo_list_len, 2);

  // A single algorithm (2 bytes)
  uint16_t sig_algo = htons(hello->sig_algo);
  memcpy(out + 53, &sig_algo, 2);

  // Return the length of the marshalled message
  return len;
}

int client_hello_send(struct tls_context *ctx) {
  struct client_hello hello;
  client_hello_init(&hello);

  uint8_t data[client_hello_marshall(&hello, NULL)];
  struct tls_record record = {.version = tls_1_2,
                              .length = sizeof(data),
                              .type = handshake,
                              .fragment = data};

  client_hello_marshall(&hello, data);

  memcpy(ctx->client_random, data + 6, sizeof(ctx->client_random));

  if (tls_context_hash_handshake(ctx, data, sizeof(data)) != 1)
    return 0;

  return tls_context_send_record(ctx, &record, NULL);
}

int server_hello_recv(struct tls_context *ctx, struct server_hello *out) {
  struct tls_record record;

  if (!tls_context_recv_record(ctx, &record))
    return 0;

  if (record.fragment[0] != 0x2) {
    tls_record_free(&record);
    return 0;
  }

  // Ensure that the out pointer is not NULL
  if (!out)
    return 0;

  // Now, we copy the data from the record fragment to the local context
  size_t offset = 4; // We use the offset to skip the message type + size field

  // Read the version from the record fragment and store it in the out struct
  out->version.major = record.fragment[offset];
  out->version.minor = record.fragment[offset + 1];
  offset += 2; 
  
  // Read the timestamp from the record fragment
  uint32_t gmt_unix_time;
  memcpy(&gmt_unix_time, record.fragment + offset, 4);
  // NOTE: Convert to host byte order
  out->random.gmt_unix_time = ntohl(gmt_unix_time); 
  offset += 4;
 
  // Copy the random bytes from the record fragment
  memcpy(out->random.random_bytes, record.fragment + offset, 28);
  offset += 28;
  
  // Save the server random bytes in the context
  memcpy(ctx->server_random, &gmt_unix_time, 4);
  memcpy(ctx->server_random + 4, out->random.random_bytes, 28);

  // Read the session ID length
  out->session_id_len = record.fragment[offset];
  offset += 1;
 
  // Copy the session ID from the record fragment
  memcpy(out->session_id, record.fragment + offset, out->session_id_len);
  offset += out->session_id_len;
  
  // Now, read the cipher suite from the record fragment
  memcpy(&out->cipher_suite, record.fragment + offset, 2);
  // NOTE: Convert to host byte order
  out->cipher_suite = ntohs(out->cipher_suite); 
  offset += 2;

  // Read the compression method
  out->compression_method = record.fragment[offset];
  offset += 1;
  
  // Hash the handshake message
  int ret = tls_context_hash_handshake(ctx, record.fragment, record.length);
  // Free resources
  tls_record_free(&record);
  // If the hashing was successful, return 1 oterwise return 0
  return ret == 1;
}

X509 *server_cert_recv(const struct tls_context *ctx) {
  struct tls_record record;

  if (!tls_context_recv_record(ctx, &record))
    return 0;

  if (record.fragment[0] != 0xb)
    goto error_handling;

  if (!tls_context_hash_handshake(ctx, record.fragment, record.length))
    goto error_handling;

  // TODO: read the certificate chain and return the first certificate (you may
  // assume that there is only one certificate) Hint: use the d2i_X509 OpenSSL
  // function to deserialize the DER-encoded structure

  // Offset to start reading the cerficate data
  // NOTE: Skip both the message type and the length field from the record fragment
  size_t offset = 4;

  // Read the length of the cerificate chain
  // NOTE: The length is stored in 3 bytes (big-endian)
  // We need also to convert the length to host byte order
  uint32_t cert_list_len = (record.fragment[offset] << 16) |
                           (record.fragment[offset + 1] << 8) |
                           record.fragment[offset + 2];
  offset += 3;

  // Read the length of the first certificate
  // NOTE: Similarly as above, we need to convert the length to host byte order
  uint32_t cert_len = (record.fragment[offset] << 16) |
                      (record.fragment[offset + 1] << 8) |
                      record.fragment[offset + 2];
  offset += 3; 

  // Ensure that the certificate length is valid
  // NOTE: The certificate length should be less than the length of the record fragment
  // as we need to read the entire certificate
  if (cert_len > record.length - offset)
    goto error_handling;
 
  // Ensure that the cerficate chain length is valid
  // NOTE: If the length of a single certificate is greater than the length of the certificate chain,
  // then there is an error
  else if (cert_len >= cert_list_len)
    goto error_handling;

  // Deserialize the DER-encoded certificate using OpenSSL d2i_X509 function
  const uint8_t *p = record.fragment + offset;
  X509 *cert = d2i_X509(NULL, &p, cert_len);
  if (!cert)
    goto error_handling;

  // Free resources
  tls_record_free(&record);
 
  // Return the certificate
  return cert;
error_handling:
  tls_record_free(&record);
  return 0;
}

int server_hello_done_recv(const struct tls_context *ctx) {
  struct tls_record record;

  if (!tls_context_recv_record(ctx, &record))
    return 0;

  if (record.fragment[0] != 0xe)
    goto error_handling;

  if (!tls_context_hash_handshake(ctx, record.fragment, record.length))
    goto error_handling;

  tls_record_free(&record);
  return 1;

error_handling:
  tls_record_free(&record);
  return 0;
}

void rsa_premaster_secret_init(struct rsa_premaster_secret *exchange) {
  // Set the minor / major version based on settings
  exchange->version.major = tls_1_2.major;
  exchange->version.minor = tls_1_2.minor;
  // Now, generate 46 random bytes for the key
  for (int i = 0; i < 46; i++)
    exchange->random[i] = rand() % 256;
}

size_t rsa_premaster_marshall(const struct rsa_premaster_secret *premaster,
                              X509 *cert, uint8_t *out) {
  size_t cipher_len = 0;
  uint8_t plain[48];

  plain[0] = premaster->version.major;
  plain[1] = premaster->version.minor;
  memcpy(plain + 2, premaster->random, 46);

  EVP_PKEY *key = X509_get_pubkey(cert);
  if (!key)
    return 0;

  EVP_PKEY_CTX *enc_ctx = EVP_PKEY_CTX_new(key, NULL);
  if (!key) {
    EVP_PKEY_free(key);
    return 0;
  }

  if (EVP_PKEY_encrypt_init(enc_ctx) <= 0)
    goto end;

  if (EVP_PKEY_CTX_set_rsa_padding(enc_ctx, RSA_PKCS1_PADDING) <= 0)
    goto end;

  if (EVP_PKEY_encrypt(enc_ctx, NULL, &cipher_len, plain, sizeof(plain)) <= 0) {
    cipher_len = 0;
    goto end;
  }

  if (!out)
    goto end;
  *out = 0x10;
  num_to_bytes(cipher_len + 2, out + 1, 3);
  num_to_bytes(cipher_len, out + 4, 2);

  if (EVP_PKEY_encrypt(enc_ctx, out + 6, &cipher_len, plain, sizeof(plain)) <=
      0)
    cipher_len = 0;

end:
  EVP_PKEY_CTX_free(enc_ctx);
  EVP_PKEY_free(key);
  return cipher_len + 6;
}

int compute_finished(struct tls_context *ctx, uint8_t *out) {
  uint8_t vrfy_seed[15 + SHA256_DIGEST_LENGTH];

  memcpy(vrfy_seed, "client finished", 15);

  if (!tls_context_handshake_digest(ctx, vrfy_seed + 15) ||
      !tls_prf(ctx->master_secret, 48, vrfy_seed, sizeof(vrfy_seed), out + 4,
               12))
    return 0;
  *out = 0x14;
  num_to_bytes(12, out + 1, 3);

  return 1;
}

int key_agreement(struct tls_context *ctx,
                  const struct rsa_premaster_secret *premaster, X509 *cert) {
  uint8_t chg_spec_msg = 0x1;
  uint8_t key_exc_frag[rsa_premaster_marshall(premaster, cert, NULL)];

  uint8_t client_verify[80];
  uint8_t vrfy[16];

  struct tls_record key_exc = {.type = handshake,
                               .version = ctx->version,
                               .length = sizeof(key_exc_frag),
                               .fragment = key_exc_frag};

  struct tls_record chg_spec = {.type = change_cipher_spec,
                                .version = ctx->version,
                                .length = 1,
                                .fragment = &chg_spec_msg};

  struct tls_record finished = {.type = handshake,
                                .length = sizeof(vrfy),
                                .version = ctx->version,
                                .fragment = vrfy};

  if (!tls_context_derive_keys(ctx, premaster) ||
      !rsa_premaster_marshall(premaster, cert, key_exc_frag) ||
      !tls_context_hash_handshake(ctx, key_exc.fragment, key_exc.length) ||
      !compute_finished(ctx, vrfy) ||
      !tls_context_hash_handshake(ctx, finished.fragment, finished.length) ||
      !tls_context_encrypt(ctx, &finished, client_verify))
    return 0;

  finished.length = sizeof(client_verify);
  finished.fragment = client_verify;
  ++ctx->client_seq;

  return tls_context_send_record(ctx, &key_exc, &chg_spec, &finished, NULL);
}

int verify_server(struct tls_context *ctx) {
  struct tls_record chg_spec;
  struct tls_record finished;
  uint8_t vrfy_seed[15 + SHA256_DIGEST_LENGTH];
  uint8_t vrfy[12];
  uint8_t received_vrfy[80];

  memcpy(vrfy_seed, "server finished", 15);

  if (!tls_context_handshake_digest(ctx, vrfy_seed + 15) ||
      !tls_prf(ctx->master_secret, 48, vrfy_seed, sizeof(vrfy_seed), vrfy,
               12) ||
      !tls_context_recv_record(ctx, &chg_spec))
    return 0;

  tls_record_free(&chg_spec);

  if (!tls_context_recv_record(ctx, &finished))
    return 0;
  if (finished.length != 80 ||
      !tls_context_decrypt(ctx, &finished, received_vrfy) ||
      memcmp(vrfy, received_vrfy + 4, 12) != 0) {
    tls_record_free(&finished);
    return 0;
  }
  tls_record_free(&finished);
  ++ctx->server_seq;

  return 1;
}

int tls_prf(const uint8_t *secret, size_t secret_len, const uint8_t *seed,
            size_t seed_len, uint8_t *out, size_t out_len) {
  uint8_t A[SHA256_DIGEST_LENGTH + seed_len];
  uint8_t result[SHA256_DIGEST_LENGTH];

  HMAC(EVP_sha256(), secret, secret_len, seed, seed_len, A, NULL);
  memcpy(A + SHA256_DIGEST_LENGTH, seed, seed_len);

  while (1) {
    HMAC(EVP_sha256(), secret, secret_len, A, SHA256_DIGEST_LENGTH + seed_len,
         result, NULL);

    if (out_len <= SHA256_DIGEST_LENGTH) {
      memcpy(out, result, out_len);
      break;
    }

    memcpy(out, result, SHA256_DIGEST_LENGTH);
    HMAC(EVP_sha256(), secret, secret_len, A, SHA256_DIGEST_LENGTH, result,
         NULL);
    memcpy(A, result, SHA256_DIGEST_LENGTH);

    out += SHA256_DIGEST_LENGTH;
    out_len -= SHA256_DIGEST_LENGTH;
  }

  return 1;
}
