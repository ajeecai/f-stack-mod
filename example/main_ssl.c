#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <assert.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "ff_config.h"
#include "ff_api.h"

#include <dlfcn.h>

// In Makefile, compile and link anet_ff
// for socket functions overriding.
extern void ff_mod_init();

typedef struct _USER_DATA
{
    int fd;
    SSL *ssl;
    int in_ssl_hs;
} USER_DATA;

#define MAX_EVENTS 512
/* kevent set */
struct kevent kevSet;
/* events */
struct kevent events[MAX_EVENTS];
/* kq */
int kq;
int sockfd;
#ifdef INET6
int sockfd6;
#endif
SSL_CTX *ctx = NULL;

char html[] =
    "HTTP/1.1 200 OK\r\n"
    "Server: F-Stack\r\n"
    "Date: Sat, 25 Feb 2017 09:26:33 GMT\r\n"
    "Content-Type: text/html\r\n"
    "Content-Length: 438\r\n"
    "Last-Modified: Tue, 21 Feb 2017 09:44:03 GMT\r\n"
    "Connection: keep-alive\r\n"
    "Accept-Ranges: bytes\r\n"
    "\r\n"
    "<!DOCTYPE html>\r\n"
    "<html>\r\n"
    "<head>\r\n"
    "<title>Welcome to F-Stack!</title>\r\n"
    "<style>\r\n"
    "    body {  \r\n"
    "        width: 35em;\r\n"
    "        margin: 0 auto; \r\n"
    "        font-family: Tahoma, Verdana, Arial, sans-serif;\r\n"
    "    }\r\n"
    "</style>\r\n"
    "</head>\r\n"
    "<body>\r\n"
    "<h1>Welcome to F-Stack!</h1>\r\n"
    "\r\n"
    "<p>For online documentation and support please refer to\r\n"
    "<a href=\"http://F-Stack.org/\">F-Stack.org</a>.<br/>\r\n"
    "\r\n"
    "<p><em>Thank you for using F-Stack.</em></p>\r\n"
    "</body>\r\n"
    "</html>";

SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int loop(void *arg)
{
    /* Wait for events to happen */
    int nevents = ff_kevent(kq, NULL, 0, events, MAX_EVENTS, NULL);
    int i;

    if (!ctx)
    {
        ctx = create_context();
        configure_context(ctx);
        ff_mod_init();
    }

    if (nevents < 0)
    {
        printf("ff_kevent failed:%d, %s\n", errno,
               strerror(errno));
        return -1;
    }

    for (i = 0; i < nevents; ++i)
    {
        struct kevent event = events[i];
        int clientfd = (int)event.ident;

        /* Handle disconnect */
        if (event.flags & EV_EOF)
        {
            USER_DATA *user_data = event.udata;
            SSL_shutdown(user_data->ssl);
            SSL_free(user_data->ssl);
            free(user_data);
            ff_close(clientfd);
#ifdef INET6
        }
        else if (clientfd == sockfd || clientfd == sockfd6)
        {
#else
        }
        else if (clientfd == sockfd)
        {
#endif
            int available = (int)event.data;
            do
            {
                int fd = ff_accept(clientfd, NULL, NULL);
                if (fd < 0)
                {
                    printf("ff_accept failed:%d, %s\n", errno,
                           strerror(errno));
                    break;
                }

                USER_DATA *user_data = malloc(sizeof(USER_DATA));
                assert(user_data);
                memset(user_data, 0, sizeof(USER_DATA));

                SSL *ssl = SSL_new(ctx);
                user_data->fd = fd;
                user_data->in_ssl_hs = 1;
                user_data->ssl = ssl;
                SSL_set_fd(ssl, fd);

                /* Add to event list */
                EV_SET(&kevSet, fd, EVFILT_READ, EV_ADD, 0, 0, user_data);

                if (ff_kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0)
                {
                    printf("ff_kevent error:%d, %s\n", errno,
                           strerror(errno));
                    return -1;
                }

                available--;
            } while (available);
        }
        else if (event.filter == EVFILT_READ)
        {
            const int len = 1024;
            char buf[len];
            memset(buf, len, 0);
            USER_DATA *user_data = event.udata;
            int fd = user_data->fd;
            SSL *ssl = user_data->ssl;
            int in_ssl_hs = user_data->in_ssl_hs;

            ERR_clear_error();
            if (in_ssl_hs)
            {
                int ret = -1;

                if ((ret = SSL_accept(ssl)) <= 0)
                {
                    int ssl_err = SSL_get_error(ssl, ret);
                    switch (ssl_err)
                    {
                    case SSL_ERROR_WANT_READ:
                        printf("SSL_ERROR_WANT_READ\n");
                        break;
                    case SSL_ERROR_WANT_WRITE:
                        printf("SSL_ERROR_WANT_WRITE\n");
                        break;
                    default:
                        printf("ssl_err is %d\n", ssl_err);
                    }
                    printf("SSL_accept: %s\n", ERR_error_string(ERR_peek_error(), NULL));
                }
                else
                {
                    user_data->in_ssl_hs = 0;
                    printf("SSL_accept: done\n");
                }

                EV_SET(&kevSet, fd, EVFILT_READ, EV_ADD, 0, 0, user_data);
                if (ff_kevent(kq, &kevSet, 1, NULL, 0, NULL) < 0)
                {
                    printf("ff_kevent error:%d, %s\n", errno,
                           strerror(errno));
                    return -1;
                }
            }
            else
            {
                USER_DATA *user_data = event.udata;
                int rlen = 0;
                if ((rlen = SSL_read(ssl, buf, len - 1)) > 0)
                {
                    buf[rlen] = 0;
                    printf("SSL read: %s", buf);
                    SSL_write(ssl, html, sizeof(html) - 1);
                }
            }
        }
        else
        {
            printf("unknown event: %8.8X\n", event.flags);
        }
    }

    return 0;
}

int main(int argc, char *argv[])
{
    ff_init(argc, argv);

    kq = ff_kqueue();
    if (kq < 0)
    {
        printf("ff_kqueue failed, errno:%d, %s\n", errno, strerror(errno));
        exit(1);
    }

    sockfd = ff_socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        printf("ff_socket failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }

    /* Set non blocking */
    int on = 1;
    ff_ioctl(sockfd, FIONBIO, &on);

    struct sockaddr_in my_addr;
    bzero(&my_addr, sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(443);
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int ret = ff_bind(sockfd, (struct linux_sockaddr *)&my_addr, sizeof(my_addr));
    if (ret < 0)
    {
        printf("ff_bind failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }

    ret = ff_listen(sockfd, MAX_EVENTS);
    if (ret < 0)
    {
        printf("ff_listen failed, sockfd:%d, errno:%d, %s\n", sockfd, errno, strerror(errno));
        exit(1);
    }

    EV_SET(&kevSet, sockfd, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    /* Update kqueue */
    ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);

#ifdef INET6
    sockfd6 = ff_socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd6 < 0)
    {
        printf("ff_socket failed, sockfd6:%d, errno:%d, %s\n", sockfd6, errno, strerror(errno));
        exit(1);
    }

    struct sockaddr_in6 my_addr6;
    bzero(&my_addr6, sizeof(my_addr6));
    my_addr6.sin6_family = AF_INET6;
    my_addr6.sin6_port = htons(80);
    my_addr6.sin6_addr = in6addr_any;

    ret = ff_bind(sockfd6, (struct linux_sockaddr *)&my_addr6, sizeof(my_addr6));
    if (ret < 0)
    {
        printf("ff_bind failed, sockfd6:%d, errno:%d, %s\n", sockfd6, errno, strerror(errno));
        exit(1);
    }

    ret = ff_listen(sockfd6, MAX_EVENTS);
    if (ret < 0)
    {
        printf("ff_listen failed, sockfd6:%d, errno:%d, %s\n", sockfd6, errno, strerror(errno));
        exit(1);
    }

    EV_SET(&kevSet, sockfd6, EVFILT_READ, EV_ADD, 0, MAX_EVENTS, NULL);
    ret = ff_kevent(kq, &kevSet, 1, NULL, 0, NULL);
    if (ret < 0)
    {
        printf("ff_kevent failed:%d, %s\n", errno, strerror(errno));
        exit(1);
    }
#endif

    ff_run(loop, NULL);
    return 0;
}
