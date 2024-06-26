#include "test_helpers.h"
#include <stdint.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "tls_impl.h"
#include "unity.h"
#include <openssl/hmac.h>


int failure = 0;
double interrupt_probability = 0;
uint8_t write_buf[2000];
uint8_t read_buf[2000];



static ssize_t limited_write(struct tls_connection *conn, const void *buf,
			     size_t count)
{
    if (failure)
	return -1;
    if ((double) rand() / (double) RAND_MAX < interrupt_probability) {
	errno = EINTR;
	return -1;
    }

    struct tls_connection_mock *mock_conn =
	(struct tls_connection_mock *) conn;
    size_t limit = count > 60 ? 60 : count;
    memcpy(write_buf + mock_conn->write_index, buf, limit);
    mock_conn->write_index += limit;
    return limit;
}

static ssize_t limited_read(struct tls_connection *conn, void *buf,
			    size_t count)
{
    if (failure)
	return -1;
    if ((double) rand() / (double) RAND_MAX < interrupt_probability) {
	errno = EINTR;
	return -1;
    }

    struct tls_connection_mock *mock_conn =
	(struct tls_connection_mock *) conn;
    size_t limit = count > 60 ? 60 : count;
    memcpy(buf, read_buf + mock_conn->read_index, limit);
    mock_conn->read_index += limit;
    return limit;
}

static int mock_close(struct tls_connection *conn)
{
    if (failure)
	return -1;
    ((struct tls_connection_mock *) conn)->closed = 1;
    return 0;
}

static const struct tls_connection_ops mock_vtable = {
    .write = limited_write,
    .read = limited_read,
    .close = mock_close,
};



void tls_connection_mock_init(struct tls_connection_mock *mock)
{
    mock->super.ops = &mock_vtable;
    mock->closed = 0;
    mock->write_index = 0;
    mock->read_index = 0;
}


void check_tls_handshake_hash(struct tls_context *ctx, uint8_t *data,
			      size_t count)
{
    uint8_t expected_hash[SHA256_DIGEST_LENGTH];
    uint8_t resulting_hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *hashing = EVP_MD_CTX_new();

    TEST_ASSERT_NOT_NULL(hashing);
    if (!EVP_DigestInit(hashing, EVP_sha256())) {
	EVP_MD_CTX_free(hashing);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!EVP_DigestUpdate(hashing, data, count)) {
	EVP_MD_CTX_free(hashing);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!EVP_DigestFinal(hashing, expected_hash, NULL)) {
	EVP_MD_CTX_free(hashing);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }

    if (!tls_context_handshake_digest(ctx, resulting_hash)) {
	EVP_MD_CTX_free(hashing);
	TEST_FAIL_MESSAGE(ERR_error_string(ERR_get_error(), NULL));
    }

    EVP_MD_CTX_free(hashing);
    TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected_hash, resulting_hash,
				     sizeof(resulting_hash),
				     "The hashing of the handshake messages is being computed wrongly");
}

void init_server_certificate(EVP_PKEY **server_key, X509 **cert)
{
    *server_key = EVP_RSA_gen(2048);
    *cert = X509_new();

    ASN1_INTEGER_set(X509_get_serialNumber(*cert), 1);
    X509_gmtime_adj(X509_get_notBefore(*cert), 0);
    X509_gmtime_adj(X509_get_notAfter(*cert), 60 * 60 * 24 * 365);
    X509_set_pubkey(*cert, *server_key);

    X509_NAME *name = X509_get_subject_name(*cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
			       (unsigned char *) "CH", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)
			       "Universita della Svizzera italiana", -1,
			       -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
			       (unsigned char *) "usi.ch", -1, -1, 0);
    X509_sign(*cert, *server_key, EVP_sha1());
}


void tls_context_mock(struct tls_context *ctx)
{
    uint8_t client_hello[] = {
	0x01, 0x00, 0x01,
	0x1e, 0x03, 0x03, 0x2f, 0x14, 0x4d, 0xaa, 0xcb,
	0xe2, 0xc4, 0xd3, 0xd1, 0xa8, 0xb1, 0x47, 0xba,
	0x33, 0xf8, 0xc8, 0xf7, 0xd1, 0x51, 0xf7, 0xa3,
	0x03, 0xc4, 0x6d, 0x96, 0xb5, 0x04, 0xf5, 0x6d,
	0x50, 0x27, 0x92, 0x20, 0x3b, 0x4b, 0x3a, 0x7c,
	0xfd, 0x4d, 0x44, 0x9f, 0x18, 0xf2, 0x5c, 0xde,
	0x2c, 0xed, 0x16, 0x16, 0x04, 0x4e, 0xbb, 0x8b,
	0x95, 0x35, 0x82, 0xb2, 0x03, 0xa8, 0x0c, 0xf6,
	0xfc, 0x8f, 0x38, 0x39, 0x00, 0x48, 0x13, 0x02,
	0x13, 0x03, 0x13, 0x01, 0x13, 0x04, 0xc0, 0x2c,
	0xc0, 0x30, 0xcc, 0xa9, 0xcc, 0xa8, 0xc0, 0xad,
	0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0xac, 0xc0, 0x23,
	0xc0, 0x27, 0xc0, 0x0a, 0xc0, 0x14, 0xc0, 0x09,
	0xc0, 0x13, 0x00, 0x9d, 0xc0, 0x9d, 0x00, 0x9c,
	0xc0, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35,
	0x00, 0x2f, 0x00, 0x9f, 0xcc, 0xaa, 0xc0, 0x9f,
	0x00, 0x9e, 0xc0, 0x9e, 0x00, 0x6b, 0x00, 0x67,
	0x00, 0x39, 0x00, 0x33, 0x00, 0xff, 0x01, 0x00,
	0x00, 0x8d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00,
	0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14,
	0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19,
	0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02,
	0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00,
	0x00, 0x16, 0x00, 0x00, 0x00, 0x17, 0x00, 0x00,
	0x00, 0x0d, 0x00, 0x22, 0x00, 0x20, 0x04, 0x03,
	0x05, 0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08,
	0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04,
	0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
	0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x00, 0x2b,
	0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00,
	0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00,
	0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xb7,
	0x9a, 0xd5, 0x30, 0x4f, 0x1b, 0x24, 0xa7, 0x7e,
	0xd1, 0x85, 0x27, 0x09, 0x2a, 0x3c, 0xa6, 0x6b,
	0x2a, 0x98, 0x2d, 0x4e, 0xf0, 0x58, 0x91, 0x1a,
	0x96, 0xa5, 0x39, 0x2d, 0x4c, 0xdd, 0x6b
    };

    uint8_t server_hello[] = {
	0x02, 0x00, 0x00,
	0x4d, 0x03, 0x03, 0xc6, 0x28, 0x3a, 0x40, 0xf6,
	0x1d, 0xf6, 0xcc, 0x52, 0x68, 0x31, 0x32, 0x53,
	0xd7, 0xb5, 0x76, 0xb2, 0xa1, 0x8e, 0xb4, 0xb4,
	0x5c, 0x9e, 0xbd, 0x8d, 0xa4, 0x0f, 0x45, 0x0b,
	0xac, 0x4e, 0x34, 0x20, 0x64, 0x48, 0x84, 0x65,
	0xff, 0xb1, 0x8a, 0x50, 0x9b, 0x82, 0x88, 0x5e,
	0x0d, 0x80, 0x93, 0x10, 0x51, 0x32, 0x4f, 0xfd,
	0x5a, 0x25, 0x99, 0xd6, 0x7c, 0x5b, 0x49, 0xa7,
	0x28, 0x3e, 0x68, 0x3e, 0x00, 0x3c, 0x00, 0x00,
	0x05, 0xff, 0x01, 0x00, 0x01, 0x00
    };

    uint8_t server_cert[] = {
	0x0b, 0x00, 0x02, 0xc9, 0x00,
	0x02, 0xc6, 0x00, 0x02, 0xc3, 0x30, 0x82, 0x02,
	0xbf, 0x30, 0x82, 0x01, 0xa7, 0x02, 0x01, 0x01,
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
	0x00, 0x30, 0x1e, 0x17, 0x0d, 0x32, 0x34, 0x30,
	0x35, 0x32, 0x30, 0x30, 0x36, 0x33, 0x39, 0x34,
	0x36, 0x5a, 0x17, 0x0d, 0x32, 0x35, 0x30, 0x35,
	0x32, 0x30, 0x30, 0x36, 0x33, 0x39, 0x34, 0x36,
	0x5a, 0x30, 0x4b, 0x31, 0x0b, 0x30, 0x09, 0x06,
	0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x43, 0x48,
	0x31, 0x2b, 0x30, 0x29, 0x06, 0x03, 0x55, 0x04,
	0x0a, 0x0c, 0x22, 0x55, 0x6e, 0x69, 0x76, 0x65,
	0x72, 0x73, 0x69, 0x74, 0x61, 0x20, 0x64, 0x65,
	0x6c, 0x6c, 0x61, 0x20, 0x53, 0x76, 0x69, 0x7a,
	0x7a, 0x65, 0x72, 0x61, 0x20, 0x69, 0x74, 0x61,
	0x6c, 0x69, 0x61, 0x6e, 0x61, 0x31, 0x0f, 0x30,
	0x0d, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x06,
	0x75, 0x73, 0x69, 0x2e, 0x63, 0x68, 0x30, 0x82,
	0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
	0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
	0x00, 0x03, 0x82, 0x01, 0x0f, 0x00, 0x30, 0x82,
	0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xdf,
	0x10, 0xcd, 0xe2, 0x00, 0x91, 0x31, 0x91, 0x25,
	0xac, 0xc5, 0x4a, 0x75, 0xfb, 0x0f, 0xa1, 0x90,
	0x58, 0x48, 0xce, 0x3e, 0x35, 0xbc, 0x99, 0x35,
	0x1d, 0x0b, 0xf6, 0x04, 0xf7, 0x91, 0x72, 0x13,
	0x1f, 0x98, 0x07, 0xfa, 0x82, 0xcf, 0xf4, 0x45,
	0x74, 0x7d, 0xc8, 0xce, 0x3f, 0x52, 0x39, 0x42,
	0x47, 0x46, 0x41, 0x30, 0x76, 0xa2, 0xf8, 0x0a,
	0x81, 0xaf, 0x3a, 0xbf, 0x68, 0x62, 0x8e, 0x80,
	0xd4, 0x12, 0xc4, 0x28, 0x8a, 0xb8, 0x97, 0x48,
	0x1a, 0x1a, 0x24, 0x58, 0x45, 0x2c, 0xad, 0x65,
	0x9c, 0x68, 0x1f, 0xca, 0x2c, 0x7a, 0xec, 0x42,
	0x89, 0x6c, 0x18, 0xf8, 0x3b, 0x87, 0xe5, 0x4d,
	0x1f, 0x8c, 0x16, 0xe4, 0x75, 0x11, 0x94, 0x90,
	0x3d, 0xab, 0x11, 0x5f, 0x8f, 0x75, 0x4e, 0xfe,
	0x47, 0x57, 0xf0, 0xce, 0x1a, 0x8a, 0x9c, 0xe3,
	0x4c, 0x40, 0xb9, 0x0b, 0x69, 0x6a, 0x20, 0x05,
	0x39, 0x01, 0x6a, 0xf9, 0x68, 0x72, 0xb3, 0xc4,
	0x3d, 0x7a, 0x0b, 0xd8, 0xd9, 0x9c, 0xdf, 0xd3,
	0xb4, 0x50, 0xcf, 0xef, 0xca, 0xb0, 0xa7, 0x56,
	0xfe, 0x94, 0x89, 0x5d, 0x32, 0x5f, 0x8d, 0x82,
	0x07, 0xaf, 0x3c, 0xdb, 0x64, 0xc2, 0x15, 0xcc,
	0xf0, 0x1c, 0x9e, 0x08, 0x53, 0xad, 0x67, 0x66,
	0x10, 0xbb, 0x58, 0x29, 0x0b, 0x45, 0x3d, 0xd6,
	0x8d, 0x3e, 0xec, 0x9a, 0xc4, 0x3a, 0xaa, 0xfa,
	0x4e, 0x4b, 0x0b, 0x58, 0x2e, 0x76, 0x5a, 0x8f,
	0xb3, 0x47, 0x44, 0x75, 0x07, 0xfa, 0x44, 0x65,
	0x67, 0xc1, 0x3c, 0x65, 0x86, 0x6c, 0x8d, 0x55,
	0x48, 0x4b, 0xfe, 0xd4, 0x2f, 0x2b, 0x1e, 0xf2,
	0x79, 0xb6, 0xd3, 0xb8, 0x14, 0x31, 0x9a, 0x0d,
	0x87, 0xa7, 0x8d, 0x31, 0x3f, 0x54, 0xc1, 0x87,
	0xbe, 0x58, 0xfb, 0x13, 0x8d, 0x71, 0x3e, 0xad,
	0x9f, 0xcb, 0x43, 0xd6, 0x1c, 0x65, 0x1f, 0x02,
	0x03, 0x01, 0x00, 0x01, 0x30, 0x0d, 0x06, 0x09,
	0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
	0x0b, 0x05, 0x00, 0x03, 0x82, 0x01, 0x01, 0x00,
	0xdc, 0x53, 0x2e, 0x25, 0xd4, 0xaa, 0xe1, 0xa9,
	0xe4, 0x12, 0x7e, 0x81, 0x93, 0x46, 0xa1, 0xc9,
	0x2e, 0x1b, 0xbf, 0x85, 0xfd, 0x3c, 0x38, 0x1a,
	0x26, 0x3a, 0xb5, 0x9c, 0x65, 0xcb, 0x87, 0x08,
	0x94, 0xd7, 0xd4, 0xe4, 0xfe, 0xb9, 0x78, 0xd1,
	0xdc, 0x4b, 0x70, 0x29, 0xb8, 0x4a, 0x1d, 0x4f,
	0x5d, 0xbb, 0x1d, 0x25, 0x69, 0x96, 0xb2, 0xea,
	0x63, 0x34, 0xac, 0x40, 0xc8, 0xcc, 0xfd, 0xdc,
	0x48, 0xb6, 0x59, 0x56, 0xce, 0xbd, 0x73, 0x7c,
	0xe0, 0x17, 0x36, 0x53, 0xda, 0x7e, 0x7c, 0x5d,
	0x3a, 0xc2, 0x4f, 0x51, 0xfe, 0x5f, 0x85, 0x71,
	0xf6, 0x05, 0xa6, 0x80, 0x94, 0x4a, 0xf7, 0x1f,
	0x33, 0xf9, 0x67, 0xc2, 0x37, 0xda, 0xcf, 0x3a,
	0xfa, 0xfc, 0x7b, 0x2e, 0xa6, 0xb8, 0x3e, 0xfb,
	0xee, 0x25, 0x56, 0x57, 0x21, 0x20, 0x2c, 0x86,
	0xfa, 0xb8, 0xd1, 0x8f, 0xff, 0x6f, 0x71, 0xa5,
	0x3a, 0x0d, 0x62, 0x20, 0x26, 0xda, 0x9a, 0x84,
	0xe0, 0xf9, 0x9f, 0x45, 0x14, 0x44, 0x2a, 0x76,
	0x5d, 0x75, 0xf0, 0x47, 0x43, 0x57, 0x5e, 0xd1,
	0x70, 0x21, 0x36, 0xe2, 0xd4, 0xb5, 0x0b, 0xf0,
	0xd8, 0x4a, 0x29, 0x73, 0x31, 0xc5, 0x3d, 0x4a,
	0x63, 0xe1, 0xa0, 0x6c, 0x51, 0x14, 0x89, 0xa6,
	0x97, 0xac, 0xbf, 0x61, 0x0d, 0xce, 0x73, 0x92,
	0xb4, 0xc7, 0xe9, 0xd8, 0x06, 0xb3, 0x4e, 0xb2,
	0xdb, 0xcd, 0xf6, 0x79, 0xcd, 0xda, 0xb9, 0xa9,
	0x4a, 0x89, 0x49, 0xd4, 0x12, 0xaa, 0xdc, 0x2e,
	0x93, 0x25, 0xf4, 0xcd, 0xed, 0x7a, 0x63, 0x91,
	0x52, 0x23, 0xd0, 0x9d, 0x8c, 0x55, 0xfc, 0xfa,
	0xbb, 0x83, 0xf7, 0xcb, 0x5a, 0x12, 0x18, 0xd4,
	0xb1, 0x0c, 0xad, 0xfb, 0x78, 0x69, 0x3c, 0x53,
	0x4d, 0x4e, 0xba, 0x99, 0xdf, 0xb0, 0x46, 0x8a,
	0xe0, 0x41, 0x9a, 0x3f, 0x5f, 0x2a, 0xd3, 0xca,
    };

    uint8_t server_done[] = { 0x0e, 0x00, 0x00, 0x00 };

    uint8_t premaster_msg[] = {
	0x10, 0x00, 0x01,
	0x02, 0x01, 0x00, 0x90, 0xf8, 0x19, 0x5d, 0x0d,
	0x02, 0xee, 0xb6, 0x91, 0x45, 0x89, 0x15, 0x40,
	0x57, 0x9d, 0x43, 0x8b, 0x0c, 0x37, 0x64, 0x9f,
	0xec, 0x06, 0x24, 0x72, 0x25, 0x6a, 0x3f, 0x2e,
	0x3e, 0xeb, 0x53, 0xc4, 0x32, 0xdb, 0x56, 0xf5,
	0xae, 0xff, 0x90, 0x59, 0xe1, 0xdd, 0x13, 0x4d,
	0x3c, 0x3d, 0x4e, 0xcb, 0x2b, 0xdc, 0x7b, 0x70,
	0x2f, 0xf1, 0x5f, 0x93, 0x8b, 0x70, 0x6a, 0xe9,
	0x4c, 0xfa, 0x45, 0xce, 0xe3, 0x03, 0xed, 0x90,
	0xea, 0xe5, 0x95, 0x3b, 0xe7, 0x33, 0x54, 0xf0,
	0x3b, 0x83, 0xd3, 0x97, 0x76, 0x73, 0x7d, 0xda,
	0x8b, 0x87, 0x21, 0xc3, 0x70, 0xa6, 0xc6, 0x44,
	0x99, 0x10, 0xad, 0xd5, 0xe8, 0xcd, 0x33, 0xb0,
	0x41, 0xc9, 0x64, 0x11, 0x97, 0x80, 0x2e, 0x38,
	0xa2, 0xc5, 0x40, 0xaf, 0x6d, 0x97, 0x1b, 0x75,
	0x4e, 0x4d, 0xbb, 0x22, 0x23, 0x57, 0xc4, 0x0a,
	0x5f, 0x24, 0x65, 0xe9, 0xd7, 0x2d, 0x47, 0xf4,
	0xee, 0x12, 0xfe, 0xe7, 0xfc, 0x44, 0xf2, 0x74,
	0xd4, 0x0c, 0x1b, 0xe8, 0xb3, 0xa7, 0x61, 0x16,
	0xfe, 0x61, 0xb1, 0x8c, 0xd0, 0x58, 0xc4, 0xfc,
	0x69, 0x9c, 0x88, 0x3a, 0x13, 0x9d, 0x5d, 0xf9,
	0xf3, 0xb9, 0xf1, 0xfc, 0xfc, 0xe2, 0x05, 0x98,
	0xc2, 0xb7, 0x6d, 0x44, 0x5e, 0xd6, 0x38, 0x19,
	0x45, 0xff, 0xbc, 0xde, 0xaf, 0xa2, 0x9e, 0x01,
	0x67, 0x8a, 0xdf, 0xe8, 0x15, 0xe3, 0x23, 0xba,
	0x51, 0x84, 0x4b, 0x90, 0x8d, 0x4a, 0x51, 0xbe,
	0xf1, 0x18, 0x38, 0x64, 0x9f, 0x3f, 0xfb, 0x6c,
	0x27, 0x28, 0x34, 0xad, 0x48, 0x48, 0x57, 0x40,
	0xd1, 0xc8, 0x8a, 0xdb, 0xbc, 0xfb, 0xa8, 0x01,
	0xbb, 0xe6, 0x5d, 0x84, 0x8f, 0x3a, 0x63, 0xd7,
	0xa3, 0xa9, 0xd4, 0x74, 0x6e, 0x5c, 0x70, 0x4b,
	0x69, 0xb2, 0xb1, 0xb5, 0x91, 0x97, 0xb3, 0x9f,
	0x74, 0x3f, 0xd7
    };

    memcpy(ctx->client_random, client_hello + 6, 32);
    memcpy(ctx->server_random, server_hello + 6, 32);

    if (!tls_context_hash_handshake
	(ctx, client_hello, sizeof(client_hello))
	|| !tls_context_hash_handshake(ctx, server_hello,
				       sizeof(server_hello))
	|| !tls_context_hash_handshake(ctx, server_cert,
				       sizeof(server_cert))
	|| !tls_context_hash_handshake(ctx, server_done,
				       sizeof(server_done))
	|| !tls_context_hash_handshake(ctx, premaster_msg,
				       sizeof(premaster_msg)))
	TEST_FAIL_MESSAGE("Failed to setup mock context");
}

void premaster_mock(struct rsa_premaster_secret *premaster)
{
    uint8_t random[] = {
	0x35, 0x1e, 0x38, 0x6e, 0xb8, 0xf4, 0xfb, 0x0e,
	0x0e, 0x57, 0xbd, 0x70, 0xd9, 0xe1, 0x16, 0x0d,
	0x97, 0x10, 0xcb, 0x22, 0xb3, 0x16, 0x46, 0x71,
	0xb6, 0x26, 0x71, 0xfb, 0xe5, 0x2d, 0x58, 0x15,
	0xad, 0xca, 0xfc, 0xb6, 0x87, 0xe6, 0x87, 0xfb,
	0xda, 0x46, 0x32, 0xd8, 0x1b, 0x91
    };
    premaster->version = tls_1_2;
    memcpy(premaster->random, random, 46);
}
