//
// Created by Theodore Ahlfeld on 2/22/16.
//

#ifndef TTUNNEL_SOCK_H
#define TTUNNEL_SOCK_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

#define INIT_SSL_LIB        SSL_library_init(); \
                            SSL_load_error_strings(); \
                            ERR_load_BIO_strings(); \
                            ERR_load_crypto_strings(); \
                            EVP_add_cipher(EVP_aes_128_cbc()); \
                            OPENSSL_config(NULL)
#define DESTROY_SSL_LIB     EVP_cleanup(); \
                            CRYPTO_cleanup_all_ex_data(); \
                            ERR_free_strings()
#define IV_LEN 16
#define KEY_LEN 16
#define FILE_NOT_FOUND -3

static char kludge;
#define WAITFORACK(s) ssl_recv(s, &kludge, 1)
#define SENDACK(s) ssl_send(s, "1", 1)

/*
 * Generates an IV for AES-CBC  encryption
 * unsigned char *iv    -> The buffer to store the IV
 * const int ivlen      -> The number of bytes for the IV
 */
void generate_IV(unsigned char *iv, const int ivlen);

/*
 * Recieves AES-CBC-128 bit encrypted file from sender and decrypts the file
 * and saves it to the file specified in the arguments
 * const sock_t sock        -> File descriptor for the senders socket
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes read and decrypted
 */
ssize_t crypto_recv_file(SSL *conn, const unsigned char *key,
                         const char *fname);

/*
 * Sends AES-CBC-128 bit encrypted file to the receiver
 * const sock_t sock        -> File descriptor for the senders socket
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes sent and encrypted
 */
ssize_t crypto_send_file(SSL *conn, char *fname, const unsigned char *key,
                         const unsigned char *iv);


/*
 * Sends AES-CBC-128 bit encrypted file to the receiver
 * const sock_t sock        -> File descriptor for the senders socket
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes sent and encrypted
 */
ssize_t ssl_send_file(SSL *conn, const char *fname);

SSL_CTX *init_ctx(const char *fname, const char *ca);

SSL *init_conn(BIO *conn, SSL_CTX *ctx);

ssize_t ssl_recv(SSL *conn, char *buf, size_t nel);

ssize_t ssl_recv_file(SSL *conn, const char *fname);

ssize_t ssl_send(SSL *conn, const char *buf, size_t len);

#endif //TTUNNEL_SOCK_H
