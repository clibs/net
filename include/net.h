
#ifndef NET_H__
#define NET_H__

#include "uv.h"
#include "tls.h"
#include "buffer/buffer.h"

#define OK 0

typedef struct net_s net_t;
typedef struct addrinfo net_ai;
typedef struct sockaddr_in socketPair_t;


#define NET_FIELDS                 \
  NET_CONNECTION_FIELDS            \
  NET_UV_FIELDS                    \
  NET_TLS_FIELDS                   \


#define NET_CONNECTION_FIELDS      \
  char *hostname;                  \
  int   port;                      \


#define NET_UV_FIELDS              \
  uv_getaddrinfo_t *resolver;      \
  uv_loop_t        *loop;          \
  uv_tcp_t         *handle;        \
  uv_write_t       *writer;        \
  uv_connect_t     *conn;          \


#define NET_TLS_FIELDS             \
  tls_t *tls;                      \
  int use_ssl;                     \


#define NET_LOG(dir, format, ...) do {                                                \
  printf("  \033[36m%s\033 : \033[90m%s\033[0m\n", dir, format, ##__VA_ARGS__);      \
}                                                                                    \
while (0)


#define NET_ERROR(dir, format, ...) do {                                              \
  printf("  \033[31m%s\031 : \033[90m%s\033[0m\n", dir, format, ##__VA_ARGS__);      \
}                                                                                    \
while (0)


#define NET_ABORT(dir, format, ...) do {       \
  NET_ERROR(dir, format, ##__VA_ARGS__);       \
  exit(-1);                                    \
}                                              \
while (0)


struct net_s {
  NET_FIELDS;
  void  *data;
  void (*conn_cb)(net_t*);
  void (*read_cb)(net_t*, size_t read, char *buf);
  void (*error_cb)(net_t*, int code);
  void (*close_cb)(uv_handle_t*);
};

/*
 * Create an new network.
 */
net_t *
net_new(char * hostname, int port);

/*
 * Set uv_loop_t for network
 */
inline int
net_set_loop(net_t * net, uv_loop_t * loop);

/*
 * Set SSL's Context
 */
int
net_set_tls(net_t * net, tls_ctx * ctx);

/*
 * Do connect to new
 */
int
net_connect(net_t * net);

/*
 * Just close the holding connection
 */
int
net_close(net_t * net, void (*cb)(uv_handle_t*));

/*
 * free connection
 */
int
net_free(net_t * net);

/*
 * real free function
 */
void
net_free_cb(uv_handle_t * handle);

/*
 * DNS resolve
 */
int
net_resolve(net_t * net);

/*
 * Default error cb
 */
void
net_error_cb(net_t * net, int err);

/*
 * DNS -> IP done, and call `net_resolve_cb`
 */
void
net_resolve_cb(uv_getaddrinfo_t *rv, int stat, net_ai * ai);

/*
 * connect created, and call `net_connect_cb`
 */
void 
net_connect_cb(uv_connect_t *conn, int stat);

/*
 * realloc buffer before you read
 */
uv_buf_t
net_alloc(uv_handle_t* handle, size_t size);

/*
 * read buffer from remote server
 */
void
net_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t buf);

/*
 * write buffer to remote server
 */
int
net_write(net_t * net, char * buf);

/*
 * return use_ssl
 */
inline int
net_use_ssl(net_t * net);

/*
 * continue to read after on data
 */
inline int
net_resume(net_t * net);

/*
 * write buffer, and call `net_write_cb`.
 */
void
net_write_cb(uv_write_t *writer, int stat);


#endif