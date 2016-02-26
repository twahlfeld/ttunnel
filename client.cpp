/*******************************************************************************
 *                                                                             *
 *       Filename:  client.cpp                                                 *
 *                                                                             *
 *    Description:  The client for a certified tunnel to server                *
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
#include <openssl/ssl.h>
#include <pthread.h>
#include "secsock.h"
#include "error.h"

#define BUFFSIZE 128
#define EXIT_LOOP -1
#define INVALD_PUT -2
#define INVALD_CMD -4
#define ENCRYPT_PUT 1
#define PLAIN_PUT 0

void print_help(const char *fname)
{
    fprintf(stderr, "%s (server name) (port) (certificate)", fname);
    exit(0);
}

char *create_serv_path(const char *hn, const char *port)
{
    const size_t hostlen = strlen(hn);
    const size_t portlen = strlen(port);
    char *full_host_path = (char *)malloc(sizeof(char)*(hostlen+portlen+2));
    strcpy(full_host_path, hn);
    memcpy(full_host_path+hostlen, ":", 2);
    strcat(full_host_path, port);
    return full_host_path;
}

int parse_cmd(SSL *conn, char *buf, size_t len)
{
    if(!strncmp(buf, "stop", 4)) return EXIT_LOOP;
    if(!strncmp(buf, "put", 3)) {
        if(buf[3] != ' ') return INVALD_PUT;
        if(buf[4] != 'N' && buf[4] != 'E') return INVALD_PUT;
        if(buf[4] == 'E' && len < 23) return INVALD_PUT;
        return ((buf[4]=='E') ? ENCRYPT_PUT : PLAIN_PUT);
    } else if (!strncmp(buf, "get", 3)) {
        if(buf[3] != ' ') return INVALD_PUT;
        if(buf[4] != 'N' && buf[4] != 'E') return INVALD_PUT;
    }
    return INVALD_CMD;
}

void *clnt_out_loop(void *data)
{
    SSL *conn = (SSL *)data;
    size_t len;
    int res;
    char buf[BUFFSIZE];
    unsigned char key[KEY_LEN];
    unsigned char iv[IV_LEN];
    char fname[BUFFSIZE];
    for (;;) {
        if (!fgets(buf, sizeof(buf)-1, stdin)) break;
        buf[len = strlen(buf)-1] = '\0';
        fprintf(stderr, "echo: %s\n", buf);
        switch(res = parse_cmd(conn, buf, len)) {
            case EXIT_LOOP:
                return nullptr;
            case INVALD_PUT:
                fprintf(stderr, "Invalid %3s format, type -h for help\n", buf);
                continue;
            case ENCRYPT_PUT:
                memcpy(key, buf+5, sizeof(key));
                generate_IV(iv, sizeof(iv));
                if(ssl_send(conn, (unsigned char *)buf, len)<=0) return nullptr;
                strcpy(fname, buf+23);
                WAITFORACK(conn);
                if(crypto_send_file(conn, fname, key, iv)==FILE_NOT_FOUND) {
                    fprintf(stderr, "Couldn't open %s", buf+15);
                    perror("");
                    break;
                }
                break;
            case PLAIN_PUT:
                fprintf(stderr, "PUT PLAIN: %s\n", buf+6);
                if(ssl_send(conn, (unsigned char *)buf, len)<=0) return nullptr;
                strcpy(fname, buf+6);
                WAITFORACK(conn);
                if(ssl_send_file(conn, fname, key, iv)==FILE_NOT_FOUND) {
                    fprintf(stderr, "Couldn't open %s", buf+15);
                    perror("");
                    break;
                }
            default:
                fprintf(stderr, "ERR=%d\n", res);
                continue;
        }

    }
    return nullptr;
}

/*void *clnt_in_loop(void *data)
{
    SSL *conn = (SSL *)data;
    char buf[BUFFSIZE];
    ssize_t len;
    for(;;) {
        if((len = ssl_recv(conn, buf, sizeof(buf))) <=0) break;
        fwrite(buf, 1, (size_t)len, stdout);
    }
    pthread_detach(pthread_self());
    return nullptr;
}*/

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
    const char *hostname = argv[1];
    const char *port = argv[2];
    const char *cert = argv[3];
    char *full_host = create_serv_path(hostname, port);

    INIT_SSL_LIB;
    BIO *conn;
    SSL_CTX *ctx = nullptr;
    while(!(ctx = init_ctx(cert)));
    SSL *ssl_conn;
    pthread_t ssl_in, ssl_out;
    ERRCHK(conn=BIO_new_connect(full_host), ==, 0, "BIO_new_connect() failed");
    free(full_host);
    ERRCHK(BIO_do_connect(conn), <=, 0, "BIO_do_connect() failed");
    ssl_conn = init_conn(conn, ctx);

    /* Creates I/O threads */
    pthread_create(&ssl_out, nullptr, clnt_out_loop, ssl_conn);
    //pthread_create(&ssl_in, nullptr, clnt_in_loop, ssl_conn);
    pthread_join(ssl_out, nullptr);
    //pthread_kill(ssl_in, 0);

    /* SSL Socket Cleanup */
    SSL_shutdown(ssl_conn);
    SSL_free(ssl_conn);
    SSL_CTX_free(ctx);
    DESTROY_SSL_LIB;
    return 0;

    seterrhandle(err);
    die_with_err(errmsg);
    return 1;
}