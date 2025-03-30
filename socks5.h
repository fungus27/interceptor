#ifndef SOCKS5_H
#define SOCKS5_H

#define __USE_GNU
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

#define SOCKS_VERSION 0x05

enum socks_error_codes {
    SOCKS_OK = 0,
    SOCKS_CONNECTION_TERMINATED = -1,
    SOCKS_INVALID_VERSION = -2,
    SOCKS_INVALID_AUTH = -3,
    SOCKS_INVALID_COMMAND = -4,
    SOCKS_INVALID_ADDRESS_TYPE = -5,
    SOCKS_DESTINATION_UNREACHABLE = -6,
    SOCKS_EXCEEDED_MAX_BUFFER_SIZE = -7,
    SOCKS_TIMEOUT = -8,
    SOCKS_INVALID_HTTP_SYNTAX = -9,
    SOCKS_SYSTEM_INTERRUPT = -10
};

enum socks_auth_methods {
    SOCKS_NO_AUTH = 0x00,
    SOCKS_UNSUITABLE = 0xff
};

enum socks_commands {
    SOCKS_CONNECT = 0x01,
    SOCKS_BIND = 0x02,
    SOCKS_UDP_ASSOCIATE = 0x03
};

enum socks_address_type {
    SOCKS_IPV4 = 0x01,
    SOCKS_DOMAINNAME = 0x03,
    SOCKS_IPV6 = 0x04
};

enum socks_replies {
    SOCKS_REP_SUCCEEDED = 0x00,
    SOCKS_REP_GENERAL_FAILURE = 0x01,
    SOCKS_REP_CONNECTION_NOT_ALLOWED = 0x02,
    SOCKS_REP_NETWORK_UNREACHABLE = 0x03,
    SOCKS_REP_HOST_UNREACHABLE = 0x04,
    SOCKS_REP_CONNECTION_REFUSED = 0x05,
    SOCKS_REP_TTL_EXPIRED = 0x06,
    SOCKS_REP_COMMAND_NOT_SUPPORTED = 0x07,
    SOCKS_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08,
};

//enum socks_poll_flags {
//    SOCKS_CPOLLIN = POLLIN,
//    SOCKS_CPOLLRDNORM = POLLRDNORM,
//    SOCKS_CPOLLRDBAND = POLLRDBAND,
//    SOCKS_CPOLLPRI = POLLPRI,
//    SOCKS_CPOLLOUT = POLLOUT,
//    SOCKS_CPOLLWRNORM = POLLWRNORM,
//    SOCKS_CPOLLWRBAND = POLLWRBAND,
//    SOCKS_CPOLLERR = POLLERR,
//    SOCKS_CPOLLHUP = POLLHUP,
//    SOCKS_CPOLLNVAL = POLLNVAL,
//
//    SOCKS_DPOLLIN = POLLIN << 16,
//    SOCKS_DPOLLRDNORM = POLLRDNORM << 16,
//    SOCKS_DPOLLRDBAND = POLLRDBAND << 16,
//    SOCKS_DPOLLPRI = POLLPRI << 16,
//    SOCKS_DPOLLOUT = POLLOUT << 16,
//    SOCKS_DPOLLWRNORM = POLLWRNORM << 16,
//    SOCKS_DPOLLWRBAND = POLLWRBAND << 16,
//    SOCKS_DPOLLERR = POLLERR << 16,
//    SOCKS_DPOLLHUP = POLLHUP << 16,
//    SOCKS_DPOLLNVAL = POLLNVAL << 16
//};
//
//struct socks_cd_connection {
//    int client_sockfd;
//    int dest_sockfd;
//};
//
//struct socks_pollfd {
//    struct socks_cd_connection fds;
//    long events, revents;
//};

const char *socks_strerror(int error);
int socks_listen(unsigned short port, unsigned int backlog);
int socks_accept(int sockfd, int timeout, struct sockaddr *client_addr);
int socks_establish_connection(int client_sockfd, int timeout, struct addrinfo *dest);
int socks_read_http_header(int sockfd, int timeout, char **buffer, size_t *length, ssize_t *content_length);
int socks_read_http_body(int sockfd, int timeout, char **buffer, ssize_t content_length, size_t *length);
int socks_read_http_message(int sockfd, int timeout, char **buffer, size_t *length);
int socks_send_http_message(int sockfd, const char *buffer, size_t length);
//int socks_poll(struct socks_pollfd *fds, nfds_t nfds, int timeout);

#endif // SOCKS5_H
