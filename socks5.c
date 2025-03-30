#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#define __USE_GNU
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include "socks5.h"

#define MAX_HTTP_HEADER_SIZE 32000
#define MAX_HTTP_BODY_SIZE 128000

const char *socks_strerror(int error) {
    switch (error) {
        case SOCKS_CONNECTION_TERMINATED:
            return "Connection terminated unexpectedly";
        case SOCKS_INVALID_VERSION:
            return "Invalid SOCKS version in header (expected 0x05)";
        case SOCKS_INVALID_AUTH:
            return "Encountered no valid authentication method in greeting";
        case SOCKS_INVALID_COMMAND:
            return "Encountered invalid command";
        case SOCKS_INVALID_ADDRESS_TYPE:
            return "Encountered invalid address type";
        case SOCKS_DESTINATION_UNREACHABLE:
            return "Destination is unreachable";
        case SOCKS_EXCEEDED_MAX_BUFFER_SIZE:
            return "Exceeded the maximum buffer size";
        case SOCKS_TIMEOUT:
            return "Connection timed out";
        case SOCKS_INVALID_HTTP_SYNTAX:
            return "Invalid HTTP syntax";
        case SOCKS_SYSTEM_INTERRUPT:
            return "Interrupted by a signal";
        default:
            return "";
    }
}

int socks_listen(unsigned short port, unsigned int backlog) {
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
    char service_port[5];
    sprintf(service_port, "%u", port);

    int error;
    if (error = getaddrinfo(NULL, service_port, &hints, &res)) {
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(error));
        exit(1);
    }

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1) {
        perror("socket failed");
        exit(1);
    }

    int yes = 1;
    if (setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes)) == -1) {
        perror("setsockopt failed");
        exit(1);
    } 

    if (bind(sockfd, res->ai_addr, res->ai_addrlen) == -1) {
        perror("bind failed");
        exit(1);
    }

    if (listen(sockfd, backlog) == -1) {
        perror("listen failed");
        exit(1);
    }
    freeaddrinfo(res);
    return sockfd;
}

int socks_accept(int sockfd, int timeout, struct sockaddr *client_addr) {
    socklen_t storage_size = sizeof(struct sockaddr_storage);

    struct pollfd pollfds[1];
    pollfds[0].fd = sockfd;
    pollfds[0].events = POLLIN;

    int status = poll(pollfds, 1, timeout);
    if (status < 0) {
        if (errno == EINTR)
            return SOCKS_SYSTEM_INTERRUPT;
        perror("poll failed");
        exit(1);
    }

    if (status == 0)
        return SOCKS_TIMEOUT;

    int client_sockfd = accept(sockfd, client_addr, &storage_size);
    if (client_sockfd == -1) {
        if (errno == ECONNABORTED)
            return SOCKS_CONNECTION_TERMINATED;
        if (errno == EINTR)
            return SOCKS_SYSTEM_INTERRUPT;

        perror("accept failed");
        exit(1);
    }
    return client_sockfd;
}

int socks_connect_to_destination(struct addrinfo *dest_info) { // TODO: maybe add timeout
    int sockfd = socket(dest_info->ai_family, dest_info->ai_socktype, dest_info->ai_protocol);
    if (sockfd == -1) {
        perror("socket failed");
        exit(1);
    }
    if (connect(sockfd, dest_info->ai_addr, dest_info->ai_addrlen) == -1) {
        switch (errno) {
            case EALREADY:
            case EBADF:
            case EINPROGRESS:
            case EISCONN:
            case ENOTSOCK:
            case EPROTOTYPE:
            case EACCES:
            case EADDRINUSE:
            case EINVAL:
            case ELOOP:
            case ENAMETOOLONG:
            case ENETDOWN:
            case ENOBUFS:
            case EOPNOTSUPP:
                perror("connect failed internally");
                exit(1);
                break;

            default:
                return -1;
        }
    }
    return sockfd;
}

// accept_less: allow receival of less data than specified
int recvn(int sockfd, void *buffer, size_t n, int timeout, char accept_less, int recv_flags) { 
    size_t received = 0;
    ssize_t bytes_read;
    struct pollfd pollfds[1];
    pollfds[0].fd = sockfd;
    pollfds[0].events = POLLIN | POLLHUP;
    while (received < n) {
        int poll_status = poll(pollfds, 1, timeout);
        if (poll_status == -1) {
            if (errno == EINTR)
                return SOCKS_SYSTEM_INTERRUPT;
            perror("poll failed");
            exit(1);
        }
        if (poll_status == 0) {
            if (accept_less)
                break;
            return SOCKS_TIMEOUT;
        }

        bytes_read = recv(sockfd, buffer, n - received, recv_flags);
        if (bytes_read == -1) {
            if (errno == EINTR)
                return SOCKS_SYSTEM_INTERRUPT;
            perror("recv failed");
            exit(1);
        }
        if (bytes_read == 0)
            return SOCKS_CONNECTION_TERMINATED;
        received += bytes_read;
        buffer += bytes_read;
    }
    return received;
}

int recv_short(int sockfd, short *out, int timeout, int flags) {
    if (recvn(sockfd, out, sizeof(short), timeout, 0, flags) == SOCKS_CONNECTION_TERMINATED)
        return SOCKS_CONNECTION_TERMINATED;
    *out = ntohs(*out);
    return SOCKS_OK;
}

int recv_long(int sockfd, long *out, int timeout, int flags) {
    if (recvn(sockfd, out, sizeof(long), timeout, 0, flags) == SOCKS_CONNECTION_TERMINATED)
        return SOCKS_CONNECTION_TERMINATED;
    *out = ntohl(*out);
    return SOCKS_OK;
}

int sendn(int sockfd, const void *message, size_t n, int flags) {
    size_t sent = 0;
    ssize_t bytes_sent;
    while (sent < n) {
        bytes_sent = send(sockfd, message, n, flags);
        if (bytes_sent == -1) {
            if (errno == ECONNRESET)
                return SOCKS_CONNECTION_TERMINATED;
            if (errno == EINTR)
                return SOCKS_SYSTEM_INTERRUPT;
            perror("send failed");
            exit(1);
        }
        sent += bytes_sent;
        message += bytes_sent;
    }
}

int send_short(int sockfd, const short message, int flags) {
    short converted = htons(message);
    return sendn(sockfd, &converted, sizeof(short), flags);
}

int send_long(int sockfd, const long message, int flags) {
    long converted = htonl(message);
    return sendn(sockfd, &converted, sizeof(long), flags);
}

int socks_establish_connection(int client_sockfd, int timeout, struct addrinfo *dest) {
    const unsigned char version = SOCKS_VERSION;
    const unsigned char method = SOCKS_NO_AUTH; // no auth (TODO: implement more methods)
    const unsigned char no_method = SOCKS_UNSUITABLE;
    int socks_code;

    // greeting
    char buf[2];
    if ((socks_code = recvn(client_sockfd, buf, 2, timeout, 0, 0)) < 0)
        return socks_code;
    if (buf[0] != SOCKS_VERSION)
        goto invalid_version;
    if (buf[1] == 0)
        goto invalid_auth;
    
    unsigned char auth_count = buf[1];
    unsigned char res_template[] = {SOCKS_VERSION, SOCKS_REP_SUCCEEDED, 0x00, SOCKS_IPV4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    char auth_methods[255];
    if ((socks_code == recvn(client_sockfd, auth_methods, auth_count, timeout, 0, 0)) < 0)
        return socks_code;
    
    char method_available = 0;
    for (unsigned int i = 0; i < auth_count; ++i)
        if (auth_methods[i] == method) {
            method_available = 1;
            break;
        }

    if (!method_available)
        goto invalid_auth;

    char greet_reply[2] = {version, method};
    if ((socks_code = sendn(client_sockfd, greet_reply, 2, 0)) < 0)
        return socks_code;
    

    // request
    struct request_header {
        unsigned char version;
        unsigned char command;
        unsigned char reserved;
        unsigned char atyp;
    };

    struct request_header client_request_header;
    if ((socks_code = recvn(client_sockfd, &client_request_header, sizeof(client_request_header), timeout, 0, 0)) < 0)
        return socks_code;
    if (client_request_header.version != SOCKS_VERSION)
        goto req_invalid_version;
    if (client_request_header.command != SOCKS_CONNECT) // TODO: implement other commands
        goto command_not_supported;
    if (client_request_header.atyp != SOCKS_IPV4 && client_request_header.atyp != SOCKS_DOMAINNAME) // TODO: ipv6
        goto address_type_not_supported;

    unsigned char address[256];
    if (client_request_header.atyp == SOCKS_IPV4) {
        if ((socks_code = recvn(client_sockfd, address, sizeof(struct in_addr), timeout, 0, 0)) < 0)
            return socks_code;
        inet_ntop(AF_INET, address, address, INET_ADDRSTRLEN);
        address[4] = 0;
    }
    else if (client_request_header.atyp == SOCKS_DOMAINNAME) {
        unsigned char domain_length;

        if ((socks_code = recvn(client_sockfd, &domain_length, 1, timeout, 0, 0)) < 0)
            return socks_code;

        if ((socks_code = recvn(client_sockfd, address, domain_length, timeout, 0, 0)) < 0)
            return socks_code;

        address[domain_length] = 0;
    }

    unsigned short port;  
    if ((socks_code = recv_short(client_sockfd, &port, timeout, 0)) < 0)
        return socks_code;
    
    // connect to destination
    char service[5];
    sprintf(service, "%u", port);

    struct addrinfo hints;
    struct addrinfo *results;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int status = getaddrinfo(address, service, &hints, &results);
    if (status != 0) {
        if (status == EAI_NONAME || status == EAI_SERVICE
                || status == EAI_FAIL || status == EAI_AGAIN
                || status == EAI_NODATA || status == EAI_ADDRFAMILY) {
            goto host_unreachable;
        } else {
            fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(status));
            exit(1);
        }
    }

    int dest_sockfd = socks_connect_to_destination(results);
    if (dest_sockfd == -1) {
        switch (errno) {
            // host unreachable
            case EADDRNOTAVAIL:
            case ETIMEDOUT:
            case EHOSTUNREACH:
                goto host_unreachable;

            // connection refused
            case ECONNREFUSED:
                goto connection_refused;

            // network unreachable
            case EAFNOSUPPORT:
            case ENETUNREACH:
                goto network_unreachable;

            case EINTR:
                return SOCKS_SYSTEM_INTERRUPT;
        }
    }

    if ((socks_code = sendn(client_sockfd, res_template, sizeof(res_template), 0)) < 0)
        return socks_code;

    memcpy(dest, results, sizeof(struct addrinfo));
    freeaddrinfo(results);
    dest->ai_next = NULL;

    return dest_sockfd;

    invalid_auth:
    sendn(client_sockfd, &version, 1, 0);
    sendn(client_sockfd, &no_method, 1, 0);
    return SOCKS_INVALID_AUTH;

    invalid_version:
    sendn(client_sockfd, &version, 1, 0);
    sendn(client_sockfd, &no_method, 1, 0);
    return SOCKS_INVALID_VERSION;

    command_not_supported:
    res_template[1] = SOCKS_REP_COMMAND_NOT_SUPPORTED;
    sendn(client_sockfd, res_template, sizeof(res_template), 0);
    return SOCKS_INVALID_COMMAND;

    address_type_not_supported:
    res_template[1] = SOCKS_REP_ADDRESS_TYPE_NOT_SUPPORTED;
    sendn(client_sockfd, res_template, sizeof(res_template), 0);
    return SOCKS_INVALID_ADDRESS_TYPE;

    req_invalid_version:
    res_template[1] = SOCKS_REP_GENERAL_FAILURE;
    sendn(client_sockfd, res_template, sizeof(res_template), 0);
    return SOCKS_INVALID_VERSION;

    host_unreachable:
    res_template[1] = SOCKS_REP_HOST_UNREACHABLE;
    sendn(client_sockfd, res_template, sizeof(res_template), 0);
    return SOCKS_DESTINATION_UNREACHABLE;

    network_unreachable:
    res_template[1] = SOCKS_REP_NETWORK_UNREACHABLE;
    sendn(client_sockfd, res_template, sizeof(res_template), 0);
    return SOCKS_DESTINATION_UNREACHABLE;

    connection_refused:
    res_template[1] = SOCKS_REP_CONNECTION_REFUSED;
    sendn(client_sockfd, res_template, sizeof(res_template), 0);
    return SOCKS_DESTINATION_UNREACHABLE;

}

// NOTE: buffer has to be freed by the caller
// content_length is set to -1 when using chunked encoding, and set to 0 when there is no body.
// otherwise its set to the length of the body
int socks_read_http_header(int sockfd, int timeout, char **buffer, size_t *length, ssize_t *content_length) {
    // NOTE: these are to remain hardcoded
    size_t current_size = 128;
    unsigned int jump = 32;

    *length = 0;
    *buffer = calloc(1, current_size); 
    char *current_ptr = *buffer;

    // 3 previous  current window
    // V           V
    // +++         +++...+++
    char *window = calloc(1, 3 + jump);
    memset(window, 1, 3);
    char *end;
    int bytes_read;

    do {
        bytes_read = recvn(sockfd, window + 3, jump, timeout, 1, MSG_PEEK);
        if (bytes_read < 0) {
            free(*buffer);
            free(window);
            return bytes_read;
        }
        end = memmem(window, 3 + jump, "\r\n\r\n", 4);
        memcpy(window, window + bytes_read, 3);
        if (end != NULL)
            bytes_read = end - window + 1;
        

        *length += bytes_read;
        while (*length >= current_size) {
            current_size *= 2;
            *buffer = realloc(*buffer, current_size);
        }
        current_ptr = *buffer + *length - bytes_read;

        int status = recvn(sockfd, current_ptr, (unsigned int)bytes_read, timeout, 0, 0);
        if (status < 0) {
            free(*buffer);
            free(window);
            return status;
        }
        //char *temp = malloc(*length + 1);
        //memcpy(temp, *buffer, *length);
        //temp[*length] = 0;
        //printf("%s - end\n\n", temp);
        //char *temp2 = malloc(jump + 4);
        //memcpy(temp2, window, jump + 3);
        //temp2[jump + 3] = 0;
        //debug_print(temp2);
        //printf("\n\n\n");
    } while (end == NULL && *length <= MAX_HTTP_HEADER_SIZE);
    
    if (*length > MAX_HTTP_HEADER_SIZE) {
        free(*buffer);
        free(window);
        return SOCKS_EXCEEDED_MAX_BUFFER_SIZE;
    }

    *buffer = realloc(*buffer, *length + 1);
    (*buffer)[*length] = 0;

    free(window);

    char *header;
    *content_length = 0;
    if ((header = strstr(*buffer, "chunked")) != NULL) {
        while (*(--header) != '\r') {
            if (header == *buffer) {
                free(*buffer);
                return SOCKS_INVALID_HTTP_SYNTAX;
            }
        }
        if (strncasecmp(header, "\r\nTransfer-Encoding:", 18) == 0) {
            *content_length = -1;
            return SOCKS_OK;
        }
    }
    if ((header = strcasestr(*buffer, "\r\nContent-Length:")) != NULL) {
        for (char *i = header + 17; *i != '\r'; ++i) {
            if (i == *buffer + *length) {
                free(*buffer);
                return SOCKS_INVALID_HTTP_SYNTAX;
            }
            if (*i == ' ')
                continue;
            if (*i > '9' || *i < '0') {
                free(*buffer);
                return SOCKS_INVALID_HTTP_SYNTAX;
            }
            *content_length *= 10;
            *content_length += *i - '0';
        }
    }

    return SOCKS_OK;
}

char hex_to_int(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

int socks_read_http_body(int sockfd, int timeout, char **buffer, ssize_t content_length, size_t *length) {
    *length = 0;
    if (content_length == 0) {
        *buffer = NULL;
        return SOCKS_OK;
    }

    if (content_length > 0) {
        *length = content_length;
        if (*length > MAX_HTTP_BODY_SIZE)
            return SOCKS_EXCEEDED_MAX_BUFFER_SIZE;
        *buffer = malloc(content_length + 1);
        int status = recvn(sockfd, *buffer, content_length, timeout, 0, 0);
        if (status < 0) {
            free(*buffer);
            return status;
        }
        (*buffer)[*length] = 0;
        return SOCKS_OK;
    }

    // TODO: maybe refactor code below
    // content_length == -1

    unsigned int chunk_size;
    size_t current_size = 128;
    *buffer = malloc(current_size);
    char *current_ptr = *buffer;
    do {
        chunk_size = 0;
        char c = 0;
        while (*length <= MAX_HTTP_BODY_SIZE) {
            ++(*length);
            while (*length >= current_size) {
                current_size *= 2;
                *buffer = realloc(*buffer, current_size);
            }
            current_ptr = *buffer + *length - 1;

            int status = recvn(sockfd, current_ptr, 1, timeout, 0, 0);
            if (status < 0) {
                free(*buffer);
                return status;
            }

            c = *current_ptr;
            
            if (c == '\r')
                break;

            char digit = hex_to_int(c);

            if (digit == -1) {
                free(*buffer);
                return SOCKS_INVALID_HTTP_SYNTAX;
            }

            
            chunk_size *= 16;
            chunk_size += digit;
        }

        if (*length > MAX_HTTP_BODY_SIZE) {
            free(*buffer);
            return SOCKS_EXCEEDED_MAX_BUFFER_SIZE;
        }

        *length += 1 + chunk_size + 2;
        while (*length >= current_size) {
            current_size *= 2;
            *buffer = realloc(*buffer, current_size);
        }
        current_ptr = *buffer + *length - (1 + chunk_size + 2);

        int status = recvn(sockfd, current_ptr, 1 + chunk_size + 2, timeout, 0, 0);
        if (status < 0) {
            free(*buffer);
            return status;
        }

    } while (chunk_size != 0 && *length <= MAX_HTTP_BODY_SIZE);

    if (*length > MAX_HTTP_BODY_SIZE) {
        free(*buffer);
        return SOCKS_EXCEEDED_MAX_BUFFER_SIZE;
    }

    *buffer = realloc(*buffer, *length + 1);
    (*buffer)[*length] = 0;

    return SOCKS_OK;
}

int socks_read_http_message(int sockfd, int timeout, char **buffer, size_t *length) {
    int status;

    size_t header_length;
    ssize_t content_length;
    char *header;
    if ((status = socks_read_http_header(sockfd, timeout, &header, &header_length, &content_length)) != SOCKS_OK)
        return status;

    size_t body_length;
    char *body;
    if ((status = socks_read_http_body(sockfd, timeout, &body, content_length, &body_length)) != SOCKS_OK)
        return status;

    *length = header_length + body_length;
    *buffer = malloc(header_length + body_length + 1);
    memcpy(*buffer, header, header_length);
    memcpy(*buffer + header_length, body, body_length);
    (*buffer)[*length] = 0;

    free(header);
    free(body);

    return SOCKS_OK;
}

int socks_send_http_message(int sockfd, const char *buffer, size_t length) {
    return sendn(sockfd, buffer, length, 0);
}
