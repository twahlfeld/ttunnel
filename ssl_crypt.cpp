//
// Created by Theodore Ahlfeld on 2/25/16.
//

#include <cstdio>
#include <cstdlib>
#include <openssl/ossl_typ.h>
#include <openssl/evp.h>
#include "secsock.h"
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
