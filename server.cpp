/*******************************************************************************
 *                                                                             *
 *       Filename:  server.cpp                                                 *
 *                                                                             *
 *    Description:  The Authentication protocol for server to cleint connection*
 *                                                                             *
 *        Version:  1.0                                                        *
 *        Created:  02/19/2016 03:30:40 PM                                     *
 *       Revision:  none                                                       *
 *         Author:  Theodore Ahlfeld (twa2108)                                 *
 *       Compiler:  gcc                                                        *
 *                                                                             *
 *   Organization:                                                             *
 *                                                                             *
 ******************************************************************************/

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include "error.h"
#include "ssl_crypt.h"
#include "secsock.h"

#define BUFFSIZE 128

void print_help(const char *fname)
{
    fprintf(stderr, "%s (port) (certificate) (root ca)", fname);
    exit(0);
}

int send_hash(SSL *conn, const char *fname)
{
    /* Send Hash of Plain Text */
    unsigned char hash[EVP_MAX_MD_SIZE];
    char hash_fname[BUFFSIZE];
    FILE *hash_file;
    size_t hash_len;
    sprintf(hash_fname, "%s.sha256", fname);
    if(!(hash_file = fopen(hash_fname, "rb"))) return 0;
    hash_len = fread(hash, sizeof(char), sizeof(hash), hash_file);
    ssl_send(conn, (char *)hash, hash_len);
    fclose(hash_file);
    return 1;
}

ssize_t recv_file(SSL *conn, char *fpath)
{
    char buf[BUFFSIZE*2];
    char *fname = fpath +strlen(fpath)-1;
    while(*(fname-1)!='/') fname--;
    ssize_t len;

    /* Creates SHA256 Hash File */
    create_hash_file(conn, fname);
    SENDACK(conn);

    /* Receive File */
    if((len = ssl_recv_file(conn, fname)) < 0) {
        if (len == FILE_NOT_FOUND) {
            sprintf(buf, "Could not create %s", fname);
        } else {
            sprintf(buf, "Error receiving file");
            perror("ssl_recv_file() failed");
        }
        return len;
    }
    sprintf(buf, "%s was successfully transferred", fname);
    ssl_send(conn, buf, strlen(buf));
    fprintf(stderr, "%s\n", buf);
    return len;
}


ssize_t send_file(SSL *conn, const char *fname)
{
    char buf[BUFFSIZE*2];
    ssize_t len;
    send_hash(conn, fname);
    WAITFORACK(conn);
    if((len = ssl_send_file(conn, fname)) < 0) {
        if(len == FILE_NOT_FOUND) {
            sprintf(buf, "Could not find file %s", fname);
        } else {
            sprintf(buf, "Error sending file");
            perror("ssl_send_file() failed");
        }
        ssl_send(conn, buf, strlen(buf));
    } else {
        sprintf(buf, "%s was sent", fname);
    }
    fprintf(stderr, "%s\n", buf);
    return len;
}



int parse_input(SSL *conn, char *input)
{
    char *cmd = strtok(input, " ");
    char *fname = strtok(nullptr, " ");
    SENDACK(conn);
    ssize_t res = 0;
    if(!strcmp(cmd, "PUT")) {
        res = recv_file(conn, fname);
    } else if(!strcmp(cmd, "GET")) {
        res = send_file(conn, fname);
    }
    return (int)res;
}

void *srv_in_loop(void *data)
{
    SSL *conn = (SSL *)data;
    char buf[BUFFSIZE];
    ssize_t len;
    ERR_clear_error();
    while(1) {
        if((len = ssl_recv(conn, buf, sizeof(buf)-1))<=0) break;
        buf[len] = '\0';
        fprintf(stderr, "%s\n", buf);
        parse_input(conn, buf);
    }
    SSL_get_shutdown(conn);
    pthread_detach(pthread_self());
    return nullptr;
}

int main(int argc, char *argv[])
{
    if(argc == 1) {
        fprintf(stderr, "Invalid Arguments\n");
        print_help(argv[0]);
    }
    if(!strcmp(argv[1],"-h")||!strcmp(argv[1],"--help")) {
        print_help(argv[0]);
    }
    if(argc < 4) {
        fprintf(stderr, "Invalid Arguments\n");
        print_help(argv[0]);
    }
    const char *port = argv[1];
    const char *cert = argv[2];
    const char *rootca = argv[3];
    int max = 3;
    INIT_SSL_LIB;
    BIO *srv = nullptr;
    BIO *clnt = nullptr;
    SSL *ssl_conn;
    SSL_CTX *ctx;
    pthread_t ssl_in;

    while(!(ctx = init_ctx(cert, rootca))&&--max);
    if(!max) {
        die_with_err("Failed Maximum Tried");
    }
    ERRCHK(srv = BIO_new_accept(port), ==, 0, "BIO_new_accept() failed");
    ERRCHK(BIO_do_accept(srv), <=, 0, "BIO_do_accept() failed");
    for(;;) {
        if(BIO_do_accept(srv) <=0 ) {
            perror("BIO_do_accept() failed");
            continue;
        }
        clnt = BIO_pop(srv);
        if(!(ssl_conn = SSL_new(ctx))) {
            perror("SSL_new() failed");
            continue;
        }
        SSL_set_bio(ssl_conn, clnt, clnt);
        if(SSL_accept(ssl_conn) <= 0) {
            perror("SSL_accept() failed");
            continue;
        }

        /* I/O threads */
        pthread_create(&ssl_in, nullptr, srv_in_loop, ssl_conn);
    }

    SSL_CTX_free(ctx);
    BIO_free(srv);
    DESTROY_SSL_LIB;
    return 0;

    seterrhandle(err);
    DESTROY_SSL_LIB;
    SSL_CTX_free(ctx);
    BIO_free(srv);
    die_with_err(errmsg);
}