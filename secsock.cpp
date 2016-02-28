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

#define SENDFIN(s) ssl_send(s, "1", 1)

/*
 * Generates an IV for AES-CBC  encryption
 * unsigned char *iv    -> The buffer to store the IV
 * const int ivlen      -> The number of bytes for the IV
 */
void generate_IV(unsigned char *iv, const int ivlen)
{
    RAND_bytes(iv, ivlen);
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
    if (!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);
        fprintf(stderr, "-Error with certificate at depth: %i\n",
                depth);
        X509_NAME_oneline(X509_get_issuer_name(cert), data, 256);
        fprintf(stderr, " issuer = %s\n", data);
        X509_NAME_oneline(X509_get_subject_name(cert), data, 256);
        fprintf(stderr, " subject = %s\n", data);
        fprintf(stderr, " err %i:%s\n", err,
                X509_verify_cert_error_string(err));
    }
    return ok;
}

SSL_CTX *init_ctx(const char *fname, const char *ca)
{
    size_t len = strlen(ca)+1;
    char *path = (char *)malloc(len);
    memcpy(path,ca, len);
    char *ca_name = path+len;
    while(*(ca_name)!='/' && ca_name != path) {
        ca_name--;
    }
    if(ca_name==path) {
        path = nullptr;
    } else {
        *(ca_name++) = '\0';
    }
    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
    ERRCHK(SSL_CTX_load_verify_locations(ctx, ca_name, path), !=, 1,
           "SSL_CTX_load_verify_locations() failed");
    ERRCHK(SSL_CTX_set_default_verify_paths(ctx), !=, 1,
           "SSL_CTX_set_default_verify_paths() failed");
    ERRCHK(SSL_CTX_use_certificate_chain_file(ctx, fname), !=, 1,
           "SSL_CTX_use_certificate_chain_file() failed");
    ERRCHK(SSL_CTX_use_PrivateKey_file(ctx, fname,
                                       SSL_FILETYPE_PEM), !=, 1,
           "SSL_CTX_use_certificate_chain_file() failed");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    SSL_CTX_set_verify_depth(ctx, 4);
    free((path?path:ca_name));
    return ctx;

    seterrhandle(err);
    free(path);
    if(errno == EINVAL) {
        fprintf(stderr, "Incorrect Password\n");
        return nullptr;
    }
    perror(errmsg);
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
    while ((len = (int)fread(plaintxt+(first?0:16), sizeof(char),
                             sizeof(ciphtxt)-(first?0:16)-1, file)) > 0) {
        EVP_CipherUpdate(&cntx, ciphtxt+1,&ciph_len,plaintxt,len+(first?0:16));
        ssl_send(conn, (char *)ciphtxt, (size_t)ciph_len+1);
        /* Last transmission of the file */
        if(len < BUFFSIZE-1) {
            if(!first && len < BUFFSIZE-16-1) break;
        }
        first++;
    }
    ERRCHK(len, ==, -1, "send() failed");
    EVP_CipherFinal(&cntx, ciphtxt+1, &ciph_len);
    ssl_send(conn, (char *)ciphtxt, (size_t)ciph_len+1);
    SENDFIN(conn);
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
 * Recieves AES-CBC-128 bit encrypted file from sender and decrypts the file
 * and saves it to the file specified in the arguments
 * const sock_t sock        -> File descriptor for the senders socket
 * const unsigned char *key -> The already instantiated AES Key for decryption
 * const unsigned char *iv  -> The initialization vector for CBC that was
 *                             received from the sender
 * returns the total amount of bytes read and decrypted
 */
ssize_t crypto_recv_file(SSL *conn, const unsigned char *key, const char *fname)
{
    int len, ciph_len, first = 0;
    size_t total = 0;
    unsigned char plaintxt[BUFFSIZE];
    unsigned char ciphtxt[BUFFSIZE];
    unsigned char iv[IV_LEN];
    EVP_CIPHER_CTX cntx;
    FILE *file;
    if((file = fopen(fname, "wb")) == nullptr) {
        return FILE_NOT_FOUND;
    }
    while ((len = (int)ssl_recv(conn,(char *)ciphtxt, sizeof(ciphtxt))-1) > 0) {
        if(!first) {
            memcpy(iv, ciphtxt+1, sizeof(iv));
            EVP_CipherInit(&cntx, EVP_aes_128_cbc(), key, iv, DECRYPT);
        }
        EVP_CipherUpdate(&cntx, plaintxt, &ciph_len, ciphtxt+1, len);
        total += fwrite(plaintxt+(first?0:16), 1,
                        (size_t)ciph_len-(first?0:16), file);

        /* Last transmission of the file */
        if(len < BUFFSIZE-1) break;
        first++;
    }
    if (len < 0) goto err;
    EVP_CipherFinal(&cntx, plaintxt, &ciph_len);
    total+=fwrite(plaintxt, 1, (size_t)ciph_len, file);
    EVP_CIPHER_CTX_cleanup(&cntx);
    WAITFORACK(conn);
    fclose(file);
    return total;

    err:
    perror("GOTHERE");
    EVP_CIPHER_CTX_cleanup(&cntx);
    die_with_err("send() failed");
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
ssize_t ssl_send_file(SSL *conn, const char *fname)
{
    ssize_t len, total = 0;
    unsigned char buf[BUFFSIZE];
    buf[0] = 'T';
    FILE *file;
    if((file = fopen(fname, "rb")) == nullptr) return FILE_NOT_FOUND;
    while ((len = (int)fread(buf+1, sizeof(char), sizeof(buf)-1, file)) > 0) {
        total += (len = ssl_send(conn, (char *)buf, (size_t)len+1))-1;
        if (len < 0) break;
    }
    SENDACK(conn);
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
    ssize_t len = 0, total = 0;
    char buf[BUFFSIZE];
    FILE *file = nullptr;
    if((file = fopen(fname, "wb")) == nullptr) return FILE_NOT_FOUND;
    while((len = ssl_recv(conn, buf, sizeof(buf))-1) > 0) {
        total += fwrite(buf+1, sizeof(char), (size_t)len, file);
    }
    fclose(file);
    if(len < 0) {
        perror("ssl_recv() failed");
        return -1;
    }
    return total;
}