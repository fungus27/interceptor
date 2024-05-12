#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>

int main() {
    struct addrinfo hints;
    struct addrinfo *results;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;

    int error;
    if (error = getaddrinfo("fung.us", "http", &hints, &results)) {
        fprintf(stderr, "ERROR: %s\n", gai_strerror(error));
        exit(1);
    }

    struct addrinfo *node = results;
    while (node) {
        char printable[INET_ADDRSTRLEN];
        if (!(inet_ntop(AF_INET, &( ((struct sockaddr_in*)node->ai_addr)->sin_addr ), printable, INET_ADDRSTRLEN)))
            fprintf(stderr, "ERROR: %s\n", strerror(errno));

        printf("%s: %s\n", node->ai_canonname, printable); 
        node = node->ai_next;
    }

    freeaddrinfo(results);
}
