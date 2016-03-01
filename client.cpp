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

#define BUFFSIZE     128
#define EXIT_LOOP   -1
#define NO_FILE     -2
#define INVALD_CMD  -8
#define NO_FLAG     -4
#define INVALD_FLAG -5
#define NO_KEY      -6
#define INVALD_KEY  -7
#define HELP         4
#define PLAIN_GET    3
#define ENCRYPT_GET  2
#define ENCRYPT_PUT  1
#define PLAIN_PUT    0

#define SERVER_FOUND_FILE(s, m)   WAITFORACK(s); \
                                  ERRCHK(kludge, ==, FILE_NOT_FOUND, m)

/*
 * Prints Help to initiate connection
 * const char *fname -> argv[0] or name of program
 */
void print_startup_help(const char *fname)
{
    fprintf(stderr, "%s (server name) (port) (certificate) (rootCA)", fname);
    exit(0);
}

/*
 * Prints example usage of the command passed in
 * const char *s    -> name of command
 */
void example(const char *s)
{
    printf("Example %s:\n"
                   "\t%s path/file.ext N\n"
                   "\t%s path/file.ext E password\n", s,s,s);
}

/*
 * Prints help on how to use the ttunnel shell
 */
void print_help()
{
    printf("There are 4 commands for the shell\n"
           "\"help\" displays this message\n"
           "\"stop\" exits the program\n"
           "\"put\" uploads a local file to the server\n"
           "\tUSAGE:\n"
           "\tput relative/file/path.ext N/(E PASSWORD)\n"
           "\tput /full/file/path.ext N/(E PASSWORD)\n\n"
           "\"get\" downloads a remote file from the server and stores it in "
                   "the current local directory\n"
           "\tUSAGE:\n"
           "\tget relative/file/path.ext N/(E PASSWORD)\n"
           "\tget /full/file/path.ext N/(E PASSWORD)\n"
           "In get/put, if the N flag is there, there must not be a password\n"
           "In get/put, if the E flag is there, there must be a password\n"
           "N means send/receive the file in plain text\n"
           "The password if used must be 8 ASCII characters\n");
    example("get");
    example("put");
}

/*
 * Creates the full server path in the form <IP>:<PORT>
 * const char *hn   -> The hostname/ip of the server
 * const char *port -> The port of the server that is running this server
 * returns the concatenated string both hostname and port
 */
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

/*
 * Sends file a file to the server
 * SSL *conn    -> The SSL connection to the server
 * const char *fname -> The name of the file to send
 * const unsigned char *key -> The 8 character password or null if sending in
 *                             plain text
 * returns 1 on success otherwise 0
 */
int send_file(SSL *conn, const char *fname, const unsigned char *key)
{
    unsigned char iv[IV_LEN];
    unsigned char hash[EVP_MAX_MD_SIZE];
    int hash_len;
    char request[BUFFSIZE];
    ssize_t res;
    generate_IV(iv, sizeof(iv));

    /* Send request */
    sprintf(request, "PUT %s", fname);
    if(ssl_send(conn, request, strlen(request))<=0) return 0;

    /* Send Hash of Plain Text */
    ERRCHK(hash_len = hash_file(fname, hash), <, 0, fname);
    WAITFORACK(conn);
    ssl_send(conn, (char *)hash, (size_t)hash_len);
    WAITFORACK(conn);

    /* Encrypt and send file */
    if(key) { // Encrpyt
        res = crypto_send_file(conn, fname, key, iv);
    } else { // Decrypt
        res = ssl_send_file(conn, fname);
    }
    ERRCHK(res, ==, FILE_NOT_FOUND, fname);
    return 1;

    seterrhandle(err);
    fprintf(stderr, "Couldn't open ");
    perror(errmsg);
    return 0;
}

/*
 * Receives file from sever and stores in current directory
 * SSL *conn    -> The servers connection
 * const char *fpath -> The path to the file
 * const unsigned char *key -> The 8 character password for encryption or null
 *                             if sending in plain text
 * returns 1 on success, otherwise 0
 */
int recv_file(SSL *conn, const char *fpath, const unsigned char *key)
{
    char request[BUFFSIZE];
    char tmpfile[BUFFSIZE];
    unsigned char local_hash[EVP_MAX_MD_SIZE];
    unsigned char srv_hash[EVP_MAX_MD_SIZE];
    ssize_t len;

    /* Send Request */
    sprintf(request, "GET %s", fpath);
    if(ssl_send(conn, request, strlen(request))<=0) return 0;

    /* Set fname to the filename only */
    const char *fname = fpath+strlen(fpath)-1;
    while(*(fname-1)!='/' && fname != fpath) fname--;
    sprintf(tmpfile, "%s.tmp", fname);

    SERVER_FOUND_FILE(conn, "Server could not find file");

    /* Get hash from server */
    ERRCHK(len = ssl_recv(conn,(char *)srv_hash, sizeof(srv_hash)), <=, 0,
           "Server failed to send hash");
    SENDACK(conn);
    if(key) { // encrypted
        ERRCHK(crypto_recv_file(conn, key, tmpfile), ==, FILE_NOT_FOUND,
               "Could not create file");
    } else {  // plain text
        ERRCHK(ssl_recv_file(conn, tmpfile), ==, FILE_NOT_FOUND,
               "Could not create");
    }
    ERRCHK(hash_file(tmpfile, local_hash),!=, len, "Hashes are different size");
    ERRCHK(memcmp(local_hash, srv_hash, len), !=, 0,"Hashes do not match");
    printf("%s was successfully received\n", fpath);
    rename(tmpfile, fpath);
    return 1;

    seterrhandle(err);
    fprintf(stderr, "%s\n", errmsg);
    remove(tmpfile);
    return 0;
}

/*
 * Prints the response from the server
 * SSL *conn    -> The SSL connection to the server
 * char *buf    -> The buffer to load the server's message into
 * size_t nel   -> The size of the buffer
 * returns 1 if message was received otherwise 0
 */
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

/*
 * Parses the command from buffer
 * char *buf          -> the buffer to parse
 * char *fname        -> buffer to copy the file name into, must be proper size
 * unsigned char *key -> buffer to copy the password into
 * returns the command interpreted or error code.
 *
 * Possible Values are
 *   Errors:
 *      INVALD_KEY      NO_FILE      INVALD_CMD      NO_FLAG      INVALD_FLAG
 *      FILE_NOT_FOUND  NO_KEY
 *   Valid:
 *      PLAIN_GET       ENCRYPT_GET  ENCRYPT_PUT     PLAIN_PUT    EXIT_LOOP
 *      HELP
 */
int parse_cmd(char *buf, char *fname, unsigned char *key)
{
    int put, encrypt;
    char *tmp = nullptr;
    if((tmp = strtok(buf, " ")) == nullptr) return INVALD_CMD;
    if(!strcmp(tmp, "stop")) return EXIT_LOOP;
    if(!strcmp(tmp, "help")) return HELP;
    if(!strcmp(tmp, "put")) {
        put = 1;
    } else if (!strcmp(tmp, "get")) {
        put = 0;
    } else {
        return INVALD_CMD;
    }
    if((tmp = strtok(nullptr, " ")) == nullptr) return NO_FILE;
    strcpy(fname, tmp);
    if(put) {
        if(access(fname, R_OK)==-1) return FILE_NOT_FOUND;
    }
    if((tmp = strtok(nullptr, " ")) == nullptr) return  NO_FLAG;
    if(tmp[0] == 'E') {
        encrypt = 1;
    } else if (tmp[0] == 'N') {
        encrypt = 0;
    } else {
        return INVALD_FLAG;
    }
    if(encrypt) {
        if((tmp = strtok(nullptr, "")) == nullptr) return NO_KEY; 
        if(strlen(tmp) != 8) return INVALD_KEY; 
        hash_str(tmp, key, KEY_LEN);
        if(put) return ENCRYPT_PUT;
        return ENCRYPT_GET;
    }
    if(put) return PLAIN_PUT;
    return PLAIN_GET;
}

/*
 * The loop for the client to input commands for the server
 * SSL *conn    -> The server's SSL Connection
 *
 * Possible Values for parse_cmd are
 *   Errors:
 *      INVALD_KEY      NO_FILE      INVALD_CMD      NO_FLAG      INVALD_FLAG
 *      FILE_NOT_FOUND  NO_KEY
 *   Valid:
 *      PLAIN_GET       ENCRYPT_GET  ENCRYPT_PUT     PLAIN_PUT    EXIT_LOOP
 *      HELP
 */
void clnt_loop(SSL *conn)
{
    char buf[BUFFSIZE];
    char fname[BUFFSIZE];
    unsigned char key[KEY_LEN];
    const unsigned char *pkey;
    buf[sizeof(buf)-1] = '\0';
    ssl_recv(conn, buf, sizeof(buf));
    printf("%s\n", buf);    // Server's Welcome
    for (;;) {
        pkey = nullptr;
        write(STDOUT_FILENO, "> ", 2);
        if (!fgets(buf, sizeof(buf)-1, stdin)) break;
        buf[strlen(buf)-1] = '\0';
        switch(parse_cmd(buf, fname, key)) {
            case EXIT_LOOP:
                return;
            case ENCRYPT_PUT:
                pkey = key;
            case PLAIN_PUT:
                if(send_file(conn, fname, pkey)) {
                    response(conn, buf, sizeof(buf));
                }
                break;
            case ENCRYPT_GET:
                pkey = key;
            case PLAIN_GET:
                if(recv_file(conn, fname, pkey)<0) {
                    response(conn, buf, sizeof(buf));
                }
                break;
            case HELP:
                print_help();
                break;
            /* ERRORS */
            case INVALD_CMD:
                fprintf(stderr, "Invalid command, type help for usage\n");
                break;
            case NO_FILE:
                fprintf(stderr, "No file specified, type help for usage\n");
                break;
            case NO_FLAG:
                fprintf(stderr, "No encryption/dercyption flag found, "
                        "type help for usage\n");
                break;
            case NO_KEY:
                fprintf(stderr, "No key for encrytion password specified, "
                        "type help for usage\n");
                break;
            case INVALD_KEY:
                fprintf(stderr, "Invalid password, must be 8 characters, "
                        "type help for usage\n");
                break;
            case FILE_NOT_FOUND:
                fprintf(stderr, "File %s could not be found\n", fname);
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
        print_startup_help(argv[0]);
    }
    if(!strcmp(argv[1],"-h")||!strcmp(argv[1],"--help")) {
        print_startup_help(argv[0]);
    }
    if(argc < 5) {
        fprintf(stderr, "Invalid Arguments\n");
        print_startup_help(argv[0]);
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
    fprintf(stderr, "Disconnecting\n");

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