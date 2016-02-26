//
// Created by Theodore Ahlfeld on 2/22/16.
//

#include <cstring>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include "error.h"
#include "secsock.h"

#define BUFFSIZE 4098
#define ENCRYPT 1
#define DECRYPT 0

/*
 * Generates an IV for AES-CBC  encryption
 * unsigned char *iv    -> The buffer to store the IV
 * const int ivlen      -> The number of bytes for the IV
 */
void generate_IV(unsigned char *iv, const int ivlen)
{
    RAND_bytes(iv, ivlen);
}


SSL_CTX *init_ctx(const char *fname)
{
    SSL_CTX *ctx = SSL_CTX_new(TLSv1_method());
    ERRCHK(SSL_CTX_use_certificate_chain_file(ctx, fname), !=, 1,
           "SSL_CTX_use_certificate_chain_file() failed");
    ERRCHK(SSL_CTX_use_PrivateKey_file(ctx, fname,
                                       SSL_FILETYPE_PEM), !=, 1,
           "SSL_CTX_use_certificate_chain_file() failed");
    return ctx;

    seterrhandle(err);
    if(errno == EINVAL) {
        fprintf(stderr, "Incorrect Password\n");
        return nullptr;
    }
    die_with_err(errmsg);
    return nullptr;
}

SSL *init_conn(BIO *conn, SSL_CTX *ctx)
{
    SSL *ssl_conn;
    ERRCHK(ssl_conn=SSL_new(ctx), ==, 0, "SSL_new() failed");
    SSL_set_bio(ssl_conn, conn, conn);
    ERRCHK(SSL_connect(ssl_conn), <=, 0, "SSL_connect() failed");

    return ssl_conn;

    seterrhandle(err);
    die_with_err(errmsg);
    return nullptr;
}

ssize_t ssl_send(SSL *conn, const char *buf, size_t len)
{
    int offset=0;
    ssize_t total = 0;
    int r;
    while(len) {
        total += (r=SSL_write(conn,buf+offset,(int)len));
        switch(SSL_get_error(conn,r)) {
            case SSL_ERROR_NONE:
                len-=r;
                offset+=r;
                return total;
            default:
                perror("SSL_send() failed");
                return -1;
        }
    }
    return -1;
}

/*
 * Sends AES-CBC-128 bit encrypted file to the receiver
 * const sock_t sock        -> File descriptor for the senders socket
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes sent and encrypted
 */
ssize_t crypto_send_file(SSL *conn, char *fname, const unsigned char *key,
                         const unsigned char *iv)
{
    int len, ciph_len=0, first=0;
    ssize_t total = 0;
    unsigned char plaintxt[BUFFSIZE];
    unsigned char ciphtxt[BUFFSIZE];
    FILE *file;
    if((file = fopen(fname, "rb")) == nullptr) return FILE_NOT_FOUND;

    EVP_CIPHER_CTX cntx;
    EVP_CipherInit(&cntx, EVP_aes_128_cbc(), key, iv, ENCRYPT);
    memcpy(plaintxt, iv, IV_LEN);
    while ((len = (int) fread(plaintxt+(first?0:16), sizeof(char),
                              (size_t)BUFFSIZE-(first?0:16), file)) > 0) {
        EVP_CipherUpdate(&cntx, ciphtxt, &ciph_len, plaintxt, len+(first?0:16));
        ssl_send(conn, (char *)ciphtxt, (size_t)ciph_len);
        /* Last transmission of the file */
        if(len < BUFFSIZE) {
            if(!first && len < BUFFSIZE-16) break;
        }
        first++;
    }
    ERRCHK(len, ==, -1, "send() failed");
    EVP_CipherFinal(&cntx, ciphtxt, &ciph_len);
    ssl_send(conn, (char *)ciphtxt, (size_t)ciph_len);
    ERRCHK(len, ==, -1, "send() failed");
    EVP_CIPHER_CTX_cleanup(&cntx);
    fclose(file);
    return total;

    seterrhandle(err);
    EVP_CIPHER_CTX_cleanup(&cntx);
    die_with_err(errmsg);
    return 1;
}

/*
 * Sends AES-CBC-128 bit encrypted file to the receiver
 * const sock_t sock        -> File descriptor for the senders socket
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes sent and encrypted
 */
ssize_t ssl_send_file(SSL *conn, char *fname)
{
    ssize_t len, total = 0;
    unsigned char buf[BUFFSIZE];
    FILE *file;
    if((file = fopen(fname, "rb")) == nullptr) return FILE_NOT_FOUND;

    while ((len = (int)fread(buf, sizeof(char), sizeof(buf), file)) > 0) {
        total += (len = ssl_send(conn, (char *)buf, (size_t) len));
        if (len < 0) break;
    }

    fclose(file);
    if(len < 0) {
        perror("ssl_send() failed");
        return -1;
    }
    return total;
}


ssize_t ssl_recv(SSL *conn, char *buf, size_t nel)
{
    int len = SSL_read(conn,buf,(int)nel);
    switch(SSL_get_error(conn,len)) {
        case SSL_ERROR_NONE:
            return len;
        case SSL_ERROR_SYSCALL: return -1;
        default:
            perror("SSL_recv() failed");
        case SSL_ERROR_ZERO_RETURN:
            return -1;
    }
}

ssize_t ssl_recv_file(SSL *conn, const char *fname)
{
    ssize_t len, total = 0;
    char buf[BUFFSIZE];
    FILE *file;
    if((file = fopen(fname, "wb")) == nullptr) return FILE_NOT_FOUND;
    while((len = ssl_recv(conn, buf, sizeof(buf)))>= 0) {
        total += fwrite(buf, sizeof(char), (size_t)len, file);
    }
    fclose(file);
    if(len < 0) {
        perror("ssl_recv() failed");
        return -1;
    }
    return total;
}