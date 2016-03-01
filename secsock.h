/*******************************************************************************
 *                                                                             *
 *       Filename:  secsock.h                                                  *
 *                                                                             *
 *    Description:  The functionality for initialization and communication of  *
 *                  SSL connections                                            *
 *                                                                             *
 *         Public:                                                             *
 *                  Certification Validation                                   *
 *                      int verify_callback(int ok, X509_STORE_CTX *store)     *
 *                                                                             *
 *                  SSL CTX initialization                                     *
 *                      SSL_CTX *init_ctx(const char *fname, const char *ca)   *
 *                                                                             *
 *                  Initialization of SSL connections                          *
 *                      SSL *init_conn(BIO *conn, SSL_CTX *ctx)                *
 *                                                                             *
 *                  Sends the specifed amount of bytes to a remote node        *
 *                      ssize_t ssl_send(SSL *conn, const char *buf,size_t len)*
 *                                                                             *
 *                  Recvs the specifed amount of byted from a remote node      *
 *                      ssize_t ssl_recv(SSL *conn, char *buf, size_t nel)     *
 *                                                                             *
 *                  Sneds a specified file to a remote node                    *
 *                      ssize_t ssl_send_file(SSL *conn, const char *fname)    *
 *                                                                             *
 *                  Recvs a file from sender and store it in the specified file*
 *                      ssize_t ssl_recv_file(SSL *conn, const char *fname)    *
 *                                                                             *
 *                  Sends a specified file encryted with AES-CBC-128 to a      *
 *                  remote node                                                *
 *                      ssize_t crypto_send_file(SSL *conn, const char *fname, *
 *                           const unsigned char *key, const unsigned char *iv)*
 *                                                                             *
 *                  Recvs a file from sender, decrypts it using AES-CBC-128    *
 *                  and stores it in the specified file                        *
 *                      ssize_t crypto_recv_file(SSL *conn,                    *
 *                           const unsigned char *key, const char *fname)      *
 *                                                                             *
 *        Version:  1.0                                                        *
 *        Created:  02/22/2016 03:30:40 PM                                     *
 *       Revision:  none                                                       *
 *         Author:  Theodore Ahlfeld (twa2108)                                 *
 *       Compiler:  gcc                                                        *
 *                                                                             *
 *   Organization:                                                             *
 *                                                                             *
 ******************************************************************************/

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

/*******************************************************************************
 *                       SSL Initilization                                     *
 *******************************************************************************
 * int verify_callback(int ok, X509_STORE_CTX *store)                          *
 * SSL_CTX *init_ctx(const char *fname, const char *ca)                        *
 * SSL *init_conn(BIO *conn, SSL_CTX *ctx)                                     *
 * ssize_t ssl_send_file(SSL *conn, const char *fname)                         *
 * ssize_t crypto_send_file(SSL *conn, const char *fname, const unsigned char  *
 *                          *key, const unsigned char *iv)                     *
 * ssize_t crypto_recv_file(SSL *conn, const unsigned char *key,               *
 *                          const char *fname)                                 *
 ******************************************************************************/

/*
 * Train of trust
 * Code was used in
 * Network Security with OpenSSL
 * by: Pravir Chandra, Matt Messier, John Viega
 */
int verify_callback(int ok, X509_STORE_CTX *store);

/*
 * Initialized the the certificate checking
 * const char *fname    -> The file name of the certificate
 * const char *ca       -> The root CA file name
 * returns the SSL CTX
 */
SSL_CTX *init_ctx(const char *fname, const char *ca);

/*
 * Initializes the connection between nodes
 * BIO *conn    -> The remote connection
 * SSL_CTX *ctx -> The SSL CTX for the connection
 */
SSL *init_conn(BIO *conn, SSL_CTX *ctx);


/*******************************************************************************
 *                       SSL Communiction Functions                            *
 *******************************************************************************
 * ssize_t ssl_send(SSL *conn, const char *buf, size_t len)                    *
 * ssize_t ssl_recv(SSL *conn, char *buf, size_t nel)                          *
 * ssize_t ssl_recv_file(SSL *conn, const char *fname)                         *
 * ssize_t ssl_send_file(SSL *conn, const char *fname)                         *
 * ssize_t crypto_send_file(SSL *conn, const char *fname, const unsigned char  *
 *                          *key, const unsigned char *iv)                     *
 * ssize_t crypto_recv_file(SSL *conn, const unsigned char *key,               *
 *                          const char *fname)                                 *
 ******************************************************************************/

/*
 * Sends message of size len to remote node
 * SSL *conn        -> The node's SSL_Connection to send the message to
 * const char *buf  -> The message to send to the remote node
 * size_t len       -> The size of the message
 */
ssize_t ssl_send(SSL *conn, const char *buf, size_t len);

/*
 * Standard SSL receive with error handling
 * SSL *conn    -> The SSL Connection of the remote node
 * char *buf    -> The buffer to store the received data
 * size_t nel   -> The size of buf
 * returns the amount of bytes received
 */
ssize_t ssl_recv(SSL *conn, char *buf, size_t nel);

/*
 * Sends Plain Text file to the receiver
 * SSL *conn                -> The SSL connection of the recipient
 * const char *fname        -> The name of the file to send
 * returns the total amount of bytes sent and encrypted
 */
ssize_t ssl_send_file(SSL *conn, const char *fname);

/*
 * Receives Plain Text file to the receiver
 * SSL *conn                -> The SSL connection of the sender
 * const char *fname        -> The name of the file to store
 * returns the total amount of bytes sent and encrypted
 */
ssize_t ssl_recv_file(SSL *conn, const char *fname);

/*
 * Sends AES-CBC-128 bit encrypted file to the receiver
 * SSL *conn                -> The SSL connection of the recipient
 * const char *fname        -> The name of the file to send
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes sent and encrypted
 */
ssize_t crypto_send_file(SSL *conn, const char *fname, const unsigned char *key,
                         const unsigned char *iv);

/*
 * Recieves AES-CBC-128 bit encrypted file from sender and decrypts the file
 * and saves it to the file specified in the arguments
 * SSL *conn                -> The SSL connection for the sender's node
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const char *fname        -> The name of the file to be stored
 * returns the total amount of bytes read and decrypted
 */
ssize_t crypto_recv_file(SSL *conn, const unsigned char *key,
                         const char *fname);

#endif //TTUNNEL_SOCK_H
