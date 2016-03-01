/*******************************************************************************
 *                                                                             *
 *       Filename:  ssl_crypt.cpp                                              *
 *                                                                             *
 *    Description:  Basic Cryptographic function such as hash and IV genetation*
 *                                                                             *
 *         Public:                                                             *
 *                  Generates a random IV                                      *
 *                      unsigned char *generate_IV(unsigned char *iv,          *
 *                              const int ivlen)                               *
 *                                                                             *
 *                  Hashes file using sha256                                   *
 *                      int hash_file(const char *fname, unsigned char *hash)  *
 *                                                                             *
 *                  Hashes a string of size len in sha256                      *
 *                      int hash_str(const char *str, unsigned char *hash,     *
 *                              size_t len)                                    *
 *                                                                             *
 *                  Creates a sha256 file and writes data to it                *
 *                      int create_hash_file(SSL *conn, const char *fname)     *
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

#ifndef TTUNNEL_SSL_CRYPT_H
#define TTUNNEL_SSL_CRYPT_H


/*
 * Generates an IV for AES-CBC  encryption
 * unsigned char *iv    -> The buffer to store the IV
 * const int ivlen      -> The number of bytes for the IV
 */
unsigned char * generate_IV(unsigned char *iv, const int ivlen);

/*
 * Hashes the file using SHA256 and stores it into the hash array argument
 * const char *path     -> The name of the file to hash
 * unsigned char *hash  -> The array to store in the hash, must be proper size
 * Returns the length of the hash
 */
int hash_file(const char *fname, unsigned char *hash);

int create_hash_file(SSL *conn, const char *fname);

int hash_str(const char *str, unsigned char *hash, size_t len);

#endif //TTUNNEL_SSL_CRYPT_H
