Network Security HW 2
Theodore Ahlfeld
twa2108

Client/Server TLS Tunnel for FTP Shell

Certificate Generation:

    ROOT CA:
        openssl req -newkey rsa:2048 -sha256 -keyout rootkey.pem -out rootreq.pem
        openssl x509 -req -in rootreq.pem -sha256 -extfile openssl.cnf -extensions v3_ca -signkey rootkey.pem -out rootcert.pem
        cat rootcert.pem rootkey.pem > root.pem
        openssl x509 -subject -issuer -noout -in root.pem

    SERVER CA SIGNED BY ROOT CA:
        openssl req -newkey rsa:2048 -sha256 -keyout serverCAkey.pem -out serverCAreq.pem
        openssl x509 -req -in serverCAreq.pem -sha256 -extfile openssl.cnf -extensions v3_ca -CA root.pem -CAkey root.pem -CAcreateserial -out serverCAcert.pem
        cat serverCAcert.pem serverCAkey.pem rootcert.pem > serverCA.pem
        openssl x509 -subject -issuer -noout -in serverCA.pem

    SERVER CERT SIGNED BY SERVER CA:
        openssl req -newkey rsa:2408 -sha256 -keyout serverkey.pem -out serverreq.pem
        openssl x509 -req -in serverreq.pem -sha256 -extfile openssl.cnf -extensions server_cert -CA serverCA.pem -CAkey serverCA.pem -CAcreateserial -out servercert.pem
        cat servercert.pem serverkey.pem serverCAcert.pem rootcert.pem > server.pem
        openssl x509 -subject -issuer -noout -in server.pem

    CLIENT CERT SIGNED BY ROOT CA:
        openssl req -newkey rsa:2048 -sha256 -keyout clientkey.pem -out clientreq.pem
        openssl x509 -req -in clientreq.pem -sha256 -extfile openssl.cnf -extensions usr_cert -CA root.pem -CAkey root.pem -CAcreateserial -out clientcert.pem
        cat clientcert.pem clientkey.pem rootcert.pem > client.pem
        openssl x509 -subject -issuer -noout -in client.pem

Compilation

    Compile server and client
    $ make

    Compile server
    $ make server

    Compile client
    $ make client

Running
    To run server
    $ ./server PORT SRV_CERT ROOTCA (optional MOTD)

    To run client
    $ ./client IP PORT CLNT_CERT ROOTCA

    There are 4 commands for the shell in client
    "help" displays this message
    "stop" exits the program
    "put" uploads a local file to the server
        USAGE:
            put relative/file/path.ext N/(E PASSWORD)
            put /full/file/path.ext N/(E PASSWORD)

    "get" downloads a remote file from the server and stores it in the current local directory
        USAGE:
            get relative/file/path.ext N/(E PASSWORD)
            get /full/file/path.ext N/(E PASSWORD)

    In get/put, if the N flag is there, there must not be a password
    In get/put, if the E flag is there, there must be a password
    N means send/receive the file in plain text
    The password if used must be 8 ASCII character
    If the file name begins with a / implies file name is full path otherwise it is relative

    Example put:
        put path/file.ext N\n"
        put /full/path/file.ext E password\n"
    Example get:
        get path/file.ext N\n"
        get /full/path/file.ext E password\n"

