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
#include "secsock.h"
#include "error.h"
#include "ssl_crypt.h"

#define BUFFSIZE 128
#define EXIT_LOOP -1
#define INVALD_PUT -2
#define INVALD_CMD -4
#define PLAIN_GET 3
#define ENCRYPT_GET 2
#define ENCRYPT_PUT 1
#define PLAIN_PUT 0

void print_help(const char *fname)
{
    fprintf(stderr, "%s (server name) (port) (certificate) (rootCA)", fname);
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

int parse_cmd(char *buf, size_t len)
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
        return ((buf[4]=='E') ? ENCRYPT_GET : PLAIN_GET);
    }
    return INVALD_CMD;
}

int send_file(SSL *conn, char *fname, const unsigned char *key)
{
    unsigned char iv[IV_LEN];
    unsigned char hash[EVP_MAX_MD_SIZE];
    int hash_len;
    char request[BUFFSIZE];
    ssize_t res;
    generate_IV(iv, sizeof(iv));
    sprintf(request, "PUT %s", fname);
    ERRCHK(hash_len = hash_file(fname, hash), <, 0, fname);
    if(ssl_send(conn, request, strlen(request))<=0) return 0;
    WAITFORACK(conn);

    /* Send Hash of Plain Text */
    ssl_send(conn, (char *)hash, (size_t)hash_len);
    WAITFORACK(conn);

    /* Encrypt and send file */
    if(key) {
        res = crypto_send_file(conn, fname, key, iv);
    } else {
        res = ssl_send_file(conn, fname);
    }
    ERRCHK(res, ==, FILE_NOT_FOUND, fname);
    return 1;

    seterrhandle(err);
    fprintf(stderr, "Couldn't open ");
    perror(errmsg);
    return 0;
}

int recv_file(SSL *conn, char *buf, const unsigned char *key)
{
    char request[BUFFSIZE];
    char tmpfile[BUFFSIZE];
    unsigned char local_hash[EVP_MAX_MD_SIZE];
    unsigned char srv_hash[EVP_MAX_MD_SIZE];
    char *fname;
    ssize_t len;
    fname = buf+strlen(buf);
    while(*(fname-1) != '/' && fname != buf) fname--;

    sprintf(request, "GET %s", buf);
    if(ssl_send(conn, request, strlen(request))<=0) return 0;
    sprintf(tmpfile, "%s.tmp", fname);
    WAITFORACK(conn);
    ERRCHK(len = ssl_recv(conn,(char *)srv_hash, sizeof(srv_hash)), <=, 0,
           "Server failed to send hash");
    SENDACK(conn);

    if(key) {
        ERRCHK(crypto_recv_file(conn, key, tmpfile), ==, FILE_NOT_FOUND,
               "Could not create file");
    } else {
        ERRCHK(ssl_recv_file(conn, tmpfile), ==, FILE_NOT_FOUND,
               "Could not create");
    }
    ERRCHK(hash_file(tmpfile, local_hash),!=, len, "Hashes are different size");
    ERRCHK(memcmp(local_hash, srv_hash, len), !=, 0,"Hashes do not match");
    printf("%s was successfully received\n", fname);
    rename(tmpfile, fname);
    return 1;

    seterrhandle(err);
    fprintf(stderr, "%s\n", errmsg);
    //remove(tmpfile);
    return 0;
}

int response(SSL *conn, char *buf, size_t nel)
{
    ssize_t len;
    if((len = ssl_recv(conn, buf, (ssize_t)nel))>0) {
        buf[len] = '\0';
        fprintf(stderr, "SERVER: %s\n", buf);
        return 1;
    }
    return 0;
}

void clnt_loop(SSL *conn)
{
    ssize_t len;
    char buf[BUFFSIZE];
    unsigned char key[KEY_LEN];
    for (;;) {
        write(STDOUT_FILENO, "> ", 2);
        if (!fgets(buf, sizeof(buf)-1, stdin)) break;
        buf[len = strlen(buf)-1] = '\0';
        hash_str(buf+6, key, sizeof(key));
        switch(parse_cmd(buf, (size_t)len)) {
            case EXIT_LOOP:
                return;
            case INVALD_PUT:
                fprintf(stderr, "Invalid %3s format, type help for help\n",buf);
                continue;
            case ENCRYPT_PUT:
                if(send_file(conn, buf+15, key)) {
                    response(conn, buf, sizeof(buf));
                }
                break;
            case PLAIN_PUT:
                if(send_file(conn, buf+6, nullptr)) {
                    response(conn, buf, sizeof(buf));
                }
                break;
            case ENCRYPT_GET:
                if(recv_file(conn, buf+15, key)<0) {
                    response(conn, buf, sizeof(buf));
                }
                break;
            case PLAIN_GET:
                if(recv_file(conn, buf+6, nullptr)<0) {
                    response(conn, buf, sizeof(buf));
                }
                break;
            default:
                break;
        }

    }
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
    if(argc < 5) {
        fprintf(stderr, "Invalid Arguments\n");
        print_help(argv[0]);
    }
    const char *hostname = argv[1];
    const char *port = argv[2];
    const char *cert = argv[3];
    const char *rootca = argv[4];
    char *full_host = create_serv_path(hostname, port);
    int tries_remaining = 3;

    INIT_SSL_LIB;
    BIO *conn;
    SSL_CTX *ctx = nullptr;
    while(!(ctx = init_ctx(cert, rootca))&&--tries_remaining);
    if(!tries_remaining) {
        die_with_err("Failed Maximum Tried");
    }
    SSL *ssl_conn;
    ERRCHK(conn=BIO_new_connect(full_host), ==, 0, "BIO_new_connect() failed");
    free(full_host);
    ERRCHK(BIO_do_connect(conn), <=, 0, "BIO_do_connect() failed");
    ssl_conn = init_conn(conn, ctx);

    clnt_loop(ssl_conn);

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