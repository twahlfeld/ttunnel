#THEODORE AHLFELD twa2108
CC  = g++
CXX = g++

INCLUDES = -I/usr/local/opt/openssl/include

CFLAGS   = -g -Wall $(INCLUDES)
CXXFLAGS = -g -Wall $(INCLUDES) -std=c++0x
LDFLAGS = -g
LDLIBS  = -lssl -lcrypto

.PHONY: default
default: client server
	rm -rf *~ a.out *.o *dSYM

ERR_SRC = error.h error.cpp



SOCK_SRC = secsock.h secsock.cpp $(ERR_SRC)

server: error.o secsock.o server.o ssl_crypt.o

client: error.o secsock.o client.o ssl_crypt.o

error.o: $(ERR_SRC)

secsock.o: $(SOCK_SRC)

server.o: server.cpp $(SOCK_SRC)

client.o: client.cpp $(SOCK_SRC)
	g++ $(CXXFLAGS) -c client.cpp -o client.o

.PHONY: clean
clean:
	rm -f *~ a.out core *.o server client

.PHONY: all
all: clean default
