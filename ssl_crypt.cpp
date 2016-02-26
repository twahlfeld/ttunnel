//
// Created by Theodore Ahlfeld on 2/25/16.
//

#include <cstdio>
#include <cstdlib>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "error.h"
#include "ssl_crypt.h"

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
    mdctx = EVP_MD_CTX_create();
    ERRCHK(fp = fopen(fname, "rb"), ==, nullptr, "fopen() failed");
    ERRCHK(mdctx = EVP_MD_CTX_create(), ==, nullptr, "EVP_MD_CTX_create() "
            "failed");
    ERRCHK(EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr), ==, 0,
           "EVP_DigestInit failed()");
    while((len = fread(buffer, 1, sizeof(buffer), fp))>0) {
        ERRCHK(EVP_DigestUpdate(mdctx, buffer, len), ==, 0,
               "EVP_DigestUpdate() failed");
    }
    EVP_DigestFinal_ex(mdctx, hash, &md_len);
    EVP_MD_CTX_destroy(mdctx);
    return md_len;
    seterrhandle(err);
    perror(errmsg);
    return -1;
}