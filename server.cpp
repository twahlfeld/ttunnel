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
#include "secsock.h"

#define BUFFSIZE 128

#define SENDACK(s) ssl_send(s, "1", 1)

void print_help(const char *fname)
{
    fprintf(stderr, "%s (port) (certificate)", fname);
    exit(0);
}

ssize_t recv_file(SSL *conn, const char *fname)
{
    char buf[BUFFSIZE*2];
    ssize_t len;
    if((len = ssl_recv_file(conn, fname)) < 0) {
        if(len == FILE_NOT_FOUND) {
            sprintf(buf, "Could not create %s", fname);
        } else {
            sprintf(buf, "Error receiving file");
            perror("ssl_recv_file() failed");
        }
    } else {
        sprintf(buf, "Copied %ld bytes to file:%s", len, fname);
    }
    ssl_send(conn, buf, strlen(buf));
    fprintf(stderr, "%s\n", buf);
    return len;
}

int parse_input(SSL *conn, char *input)
{
    FILE *file;
    char *cmd = strtok(input, " ");
    char *fname;
    ssize_t res;
    if(!strcmp(cmd, "put")) {
        if(cmd[0]=='E') {
            cmd = strtok(input, " ");
        }
        SENDACK(conn);
        fname = strtok(input, " ");
        recv_file(conn, fname);
    }
}

void *srv_in_loop(void *data)
{
    SSL *conn = (SSL *)data;
    char buf[BUFFSIZE];
    ssize_t len;
    ERR_clear_error();
    while(1) {
        if((len = ssl_recv(conn, buf, sizeof(buf)))<=0) break;
        write(STDERR_FILENO, buf, (size_t)len);
        parse_input(conn, buf);
    }
    SSL_get_shutdown(conn);
    pthread_detach(pthread_self());
    return nullptr;
}

void *srv_out_loop(void *data)
{
    SSL *conn = (SSL *)data;
    char buf[BUFFSIZE];
    ERR_clear_error();
    for (;;) {
        if (!fgets(buf, sizeof(buf)-1, stdin)) break;
        ssl_send(conn, buf, strlen(buf));
    }
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
    if(argc < 3) {
        fprintf(stderr, "Invalid Arguments\n");
        print_help(argv[0]);
    }
    const char *port = argv[1];
    const char *cert = argv[2];

    INIT_SSL_LIB;
    BIO *srv = nullptr;
    BIO *clnt = nullptr;
    SSL *ssl_conn;
    SSL_CTX *ctx;
    pthread_t ssl_in, ssl_out;
    while(!(ctx = init_ctx(cert)));
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
        pthread_create(&ssl_out, nullptr, srv_out_loop, ssl_conn);
    }

    SSL_CTX_free(ctx);
    BIO_free(srv);
    return 0;

    seterrhandle(err);
    SSL_CTX_free(ctx);
    BIO_free(srv);
    die_with_err(errmsg);
}