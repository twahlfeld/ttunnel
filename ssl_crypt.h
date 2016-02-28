//
// Created by Theodore Ahlfeld on 2/25/16.
//

#ifndef TTUNNEL_SSL_CRYPT_H
#define TTUNNEL_SSL_CRYPT_H

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
