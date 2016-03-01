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

#include <cstdio>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "secsock.h"
#include "error.h"
#include "ssl_crypt.h"

/*
 * Generates an IV for AES-CBC  encryption
 * unsigned char *iv    -> The buffer to store the IV
 * const int ivlen      -> The number of bytes for the IV
 * returns the address of iv
 */
unsigned char *generate_IV(unsigned char *iv, const int ivlen)
{
    RAND_bytes(iv, ivlen);
    return iv;
}

/*
 * Hashes the file using SHA256 and stores it into the hash array argument
 * const char *path     -> The name of the file to hash
 * unsigned char *hash  -> The array to store in the hash, must be proper size
 * Returns the length of the hash
 */
int hash_file(const char *fname, unsigned char *hash)
{
    unsigned buffer[4096];
    FILE *fp;
    size_t len = 0;
    EVP_MD_CTX *mdctx = nullptr;
    unsigned int md_len = 0;
    ERRCHK(fp = fopen(fname, "rb"), ==, nullptr, nullptr);
    ERRCHK(mdctx = EVP_MD_CTX_create(), ==, nullptr, "EVP_MD_CTX_create() "
            "failed");
    ERRCHK(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr), ==, 0,
           "EVP_DigestInit failed()");
    while((len = fread(buffer, 1, sizeof(buffer), fp))>0) {
        ERRCHK(EVP_DigestUpdate(mdctx, buffer, len), ==, 0,
               "EVP_DigestUpdate() failed");
    }
    fclose(fp);
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    return md_len;
    seterrhandle(err);
    if(errmsg) {
        perror(errmsg);
    }
    return -1;
}

/*
 * Hashes a string of to a hash of size len using sha256
 * const char *str      -> The string to hash
 * unsgined char *hash  -> The array to store the hash, must be proper size
 * size_t len           -> The amount of bytes to hash
 */
int hash_str(const char *str, unsigned char *hash, size_t len)
{
    unsigned char buffer[EVP_MAX_MD_SIZE];
    memcpy(buffer, str, 8);
    memcpy(buffer+8, str, 8);
    memcpy(buffer+16, str, 8);
    memcpy(buffer+24, str, 8);
    unsigned char *md = (unsigned char *)((void *)buffer);
    unsigned int md_len = 0;
    EVP_MD_CTX *mdctx = nullptr;
    ERRCHK(mdctx = EVP_MD_CTX_create(), ==, nullptr, "EVP_MD_CTX_create() "
            "failed");
    ERRCHK(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr), ==, 0,
           "EVP_DigestInit failed()");
    ERRCHK(EVP_DigestUpdate(mdctx, buffer, sizeof(buffer)), ==, 0,
           "EVP_DigestUpdate() failed");
    EVP_DigestFinal_ex(mdctx, md, &md_len);
    memcpy(hash, md, len);
    EVP_MD_CTX_destroy(mdctx);
    return md_len;
    seterrhandle(err);
    perror(errmsg);
    return 0;
}

/*
 * Crates a sha256 file and reads data from the SSL connection to write from
 * SSL *conn            -> The SSL connection fo the remote node
 * const char *fname    -> The name of the file to hash
 */
int create_hash_file(SSL *conn, const char *fname)
{
    ssize_t len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    char hash_file[128];
    sprintf(hash_file, "%s.sha256", fname);
    FILE *fp = fopen(hash_file, "wb");
    if((len = ssl_recv(conn, (char *)hash, sizeof(hash))) <= 0) return 0;
    fwrite(hash, sizeof(char), (size_t)len, fp);
    fclose(fp);
    return 1;
}
