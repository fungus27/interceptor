#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

#include "socks5.h"

// TODO: implement ipv6 support
// TODO: replace short and longs with appropriate types
// TODO: log clientnames
// TODO: intercept only http traffic

char interrupt_flag = 0;

void terminate_connection(int sockfd) {
    if (close(sockfd) == -1) {
        perror("close");
        exit(1);
    }
}

void remove_closed_sockets(struct pollfd *connections, unsigned int length) {
    struct pollfd *copy = malloc(length * sizeof(struct pollfd));
    memcpy(copy, connections, length * sizeof(struct pollfd));
    unsigned int j = 0;
    for (unsigned int i = 0; i < length; ++i) {
        if (copy[i].fd != -1) {
            memcpy(&connections[j], &copy[i], sizeof(struct pollfd));
            ++j;
        }
    }
    free(copy);
}

void set_interrupt_flag(int sig) {
    interrupt_flag = 1;
}

void debug_print(const char *s) {
    char c;
    for (c = *s; c != 0; c = *(++s)) {
        if (c == '\n')
            printf("\\n");
        else if (c == '\r')
            printf("\\r");
        else
            putchar(c);
    }
}

void editor_modify_message(char *http_message, size_t length) {
    const char *template = "/tmp/interceptor_request.XXXXXX";
    char filename[64];
    memcpy(filename, template, strlen(template) + 1);

    int temp_file = mkstemp(filename);
    if (temp_file == -1) {
        perror("mkstemp failed");
        exit(1);
    }

    pid_t pid = fork();

    if (pid == -1) {
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // TODO: check if the file was modified before opening it
        execl("/bin/nvim", "nvim", "-c", "\":set fileformat=dos\"", filename, (char*)NULL); // TODO: set fileformat=dos
    } else {
        // write message into temp file
        size_t written = 0;
        while (written < length) {
            ssize_t status = write(temp_file, http_message + written, length - written);
            if (status == -1) {
                if (status == EINTR)
                    break;
                perror("write failed");
                exit(1);
            }
            written += status;
        }

        int status;
        waitpid(pid, &status, 0);
        if (!WIFEXITED(status)) {
            fprintf(stderr, "child process terminated in an unexpected way\n");
            exit(1);
        }

        // read and modify/check the file 

        FILE *stream = fdopen(temp_file, "r");
        if (stream == NULL) {
            perror("fdopen failed");
            exit(1);
        }

        status = fseek(stream, 0, SEEK_END);
        if (status == -1) {
            perror("fseek failed");
            exit(1);
        }

        long file_size = ftell(stream);
        if (file_size == -1) {
            perror("ftell failed");
            exit(1);
        }

        status = fseek(stream, 0, SEEK_SET);
        if (status == -1) {
            perror("fseek failed");
            exit(1);
        }

        // TODO: check/modify
        http_message = realloc(http_message, file_size + 1);
        http_message[file_size] = 0;
        size_t read = fread(http_message, 1, file_size, stream);
        if (read < file_size) {
            fprintf(stderr, "fread failed with an unknown error\n");
            exit(1);
        }

        if (fclose(stream) == EOF) {
            perror("fclose failed");
            exit(1);
        }
    }
}

int main() {
    signal(SIGINT, set_interrupt_flag);

    const unsigned int max_connection_count = 12;
    int host_sockfd = socks_listen(9050, max_connection_count);
    struct pollfd connections[max_connection_count * 2];
    unsigned int connection_count = 0;

    struct sockaddr addr;
    struct addrinfo addrinfo;
    while (!interrupt_flag) {
        // accept incoming connections

        while (1) {
            int client_sockfd = socks_accept(host_sockfd, 10, &addr);

            if (client_sockfd >= 0 && connection_count < max_connection_count) {
                int dest_sockfd = socks_establish_connection(client_sockfd, 300, &addrinfo);
                if (dest_sockfd >= 0) {
                    connections[connection_count * 2] = (struct pollfd){.fd = client_sockfd, .events = POLLIN | POLLHUP, .revents = 0};
                    connections[connection_count * 2 + 1] = (struct pollfd){.fd = dest_sockfd, .events = POLLIN | POLLHUP, .revents = 0};
                    ++connection_count;
                } else {
                    printf("[log] failed to establish connection with host: %s\n", socks_strerror(dest_sockfd));
                    terminate_connection(client_sockfd);
                }
            } else if (client_sockfd == SOCKS_TIMEOUT || connection_count > max_connection_count)
                break;
        }

        // poll existing connections
        int polled = poll(connections, connection_count * 2, 500);
        if (polled < 0) {
            if (errno == EINTR)
                break;
            perror("poll failed");
            exit(1);
        } 
        unsigned int handled = 0;
        unsigned int closed = 0;
        for (unsigned int i = 0; handled < polled; ++i) {
            if (connections[i].fd == -1) {
                if (connections[i].revents != 0)
                    ++handled;
                continue;
            }

            unsigned int dest_idx = (i % 2 == 0) ? i + 1 : i - 1;

            if (connections[i].revents & POLLHUP) {
                close_connection:
                printf("[log] closed connection\n");
                terminate_connection(connections[i].fd);
                terminate_connection(connections[dest_idx].fd);
                connections[i].fd = -1;
                connections[dest_idx].fd = -1;
                ++handled;
                closed += 2;
            } else if (connections[i].revents & POLLIN) {
                char *http_message;
                size_t length;

                int status = socks_read_http_message(connections[i].fd, 60000, &http_message, &length);
                if (status < 0 && status != SOCKS_SYSTEM_INTERRUPT) {
                    if (status != SOCKS_CONNECTION_TERMINATED)
                        printf("[log] received invalid http message: %s\n", socks_strerror(status));
                    goto close_connection;
                }
                
                if (i % 2 == 0) {
                    editor_modify_message(http_message, length);
                }

                status = socks_send_http_message(connections[dest_idx].fd, http_message, length);
                if (status < 0) {
                    printf("[log] could not send an http message back: %s\n", socks_strerror(status));
                    goto close_connection;
                }

                free(http_message);
                ++handled;
            }
        }

        // remove closed connections from the queue
        remove_closed_sockets(connections, connection_count * 2);
        connection_count -= closed/2;
    }

    if (interrupt_flag)
        printf("\nKeyboard interrupt (quitting)\n");

    for (unsigned int i = 0; i < connection_count; ++i)
        terminate_connection(connections[i].fd);
}
