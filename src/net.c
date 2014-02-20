
#include "uv.h"
#include "net.h"

net_t *
net_new(char * hostname, int port) {
  net_t * net = (net_t*) malloc(sizeof(net_t));
  net->loop = uv_default_loop();
  net->hostname = hostname;
  net->port = port;
  net->use_ssl = 0;
  net->conn_cb = NULL;
  net->read_cb = NULL;
  return net;
}

int
net_set_tls(net_t * net, tls_ctx * ctx) {
  net->use_ssl = USE_SSL;
  net->tls = tls_create(ctx);
  return OK;
}

int
net_connect(net_t * net) {
  net_resolve(net);
  return OK;
}

int
net_close(net_t * net, void (*cb)(uv_handle_t*)) {
  net->close_cb = cb;
  uv_close((uv_handle_t*)net->handle, net->close_cb);
  return OK;
}

int
net_free(net_t * net) {
  net_close(net, net_free_cb);
  return OK;
}

void
net_free_cb(uv_handle_t * handle) {
  net_t * net = (net_t *) handle->data;
  tls_free(net->tls);
  free(net->handle);
  free(net->writer);
  free(net->conn);
  free(net->resolver);
  free(net);
}

int 
net_resolve(net_t * net) {
  net_ai hints;
  int ret;
  char buf[6];

  snprintf(buf, 6, "%d", net->port);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  net->resolver = malloc(sizeof(uv_getaddrinfo_t));
  if (!net->resolver) {
    /*
     * TODO(Yorkie): depent parital handles
     */
    abort();
    return -1;
  }

  net->resolver->data = (void *) net;
  ret = uv_getaddrinfo(net->loop, net->resolver, 
    net_resolve_cb, net->hostname, NULL, &hints);

  return ret;
}

void
net_resolve_cb(uv_getaddrinfo_t *rv, int stat, net_ai * ai) {
  net_t * net = (net_t*) rv->data;
  socketPair_t dest;
  char addr[INET6_ADDRSTRLEN];
  int ret;

  if (stat < 0) {
    /*
     * TODO(Yorkie): depent partial handles
     */
    abort();
  }

  net->handle = (uv_tcp_t *) malloc(sizeof(uv_tcp_t));
  net->writer = (uv_write_t *) malloc(sizeof(uv_write_t));
  net->conn   = (uv_connect_t *) malloc(sizeof(uv_connect_t));

  net->handle->data 
   = net->writer->data
   = net->conn->data
   = (void *) net;

  NET_LOG("net", "resolving name");
  uv_ip4_name((socketPair_t *) ai->ai_addr, addr, INET6_ADDRSTRLEN);
  dest = uv_ip4_addr(addr, net->port);

  /*
   * create tcp instance.
   */
  uv_tcp_init(net->loop, net->handle);
  ret = uv_tcp_connect(net->conn, net->handle, dest, net_connect_cb);
  if (ret != OK) {
    /*
     * TODO(Yorkie): Should export corresponding error string.
     */
     abort();
  }

  /*
   * free
   */
  uv_freeaddrinfo(ai);
}

void 
net_connect_cb(uv_connect_t *conn, int stat) {
  net_t * net = (net_t *) conn->data;
  int read;

  if (stat < 0) {
    /*
     * TODO(Yorkie): Should export corresponding error message.
     */
    abort();
  }

  /*
   * read buffers via uv
   */
  uv_read_start((uv_stream_t *) net->handle, 
    net_alloc, net_read);
  NET_LOG("net", "TCP Connection established");

  /*
   * call `conn_cb`, the tcp connection has been 
   *  established in user-land.
   */
  if (net->use_ssl == NOT_SSL && net->conn_cb != NULL) {
    net->conn_cb(net);
  }

  /*
   * Handle TLS Partial
   */
  if (net->use_ssl == USE_SSL && tls_connect(net->tls) == OK) {
    read = 0;
    do {
      read = tls_bio_read(net->tls, 0);
      if (read > 0) {
        uv_buf_t uvbuf = uv_buf_init(net->tls->buf, read);
        uv_write(net->writer, (uv_stream_t*)net->handle, &uvbuf, 1, NULL);
      }
    } 
    while (read > 0);
  }
}

uv_buf_t
net_alloc(uv_handle_t* handle, size_t size) {
  char * base = (char *) calloc(size, 1);
  return uv_buf_init(base, size);
}

void
net_read(uv_stream_t *handle, ssize_t nread, const uv_buf_t buf) {
  net_t * net = (net_t *) handle->data;

  if (nread < 0) {
    /*
     * TODO(Yorkie): destroy connection ? or user-land?
     */
    abort();
  }

  /* 
   * BIO Return rule:
   * All these functions return either the amount of data successfully
   * read or written (if the return value is positive) or that no data 
   * was successfully read or written if the result is 0 or -1. If the 
   * return value is -2 then the operation is not implemented in the specific BIO type.
   */
  if (net->use_ssl) {
    net->tls->data = malloc(1);

    tls_bio_write(net->tls, buf.base, nread);
    free(buf.base);

    int read = 0;
    int stat = tls_read(net->tls);
    if (stat == 1) {
      /* 
       * continue: Say hello
       */
      do {
        read = tls_bio_read(net->tls, 0);
        if (read > 0) {
          uv_buf_t uvbuf = uv_buf_init(net->tls->buf, read);
          uv_write(net->writer, (uv_stream_t*)net->handle, &uvbuf, 1, NULL);
        }
      } 
      while (read > 0);
    
    } else if (stat == 0) {
      /*
       * SSL Connection is created
       * Here need to call user-land callback
       */
      uv_read_stop((uv_stream_t*)net->handle);
      if (net->read_cb != NULL) {
        net->read_cb(net, buffer_length(net->tls->buffer), buffer_string(net->tls->buffer));
      }

    } else if (stat == -1) {
      /*
       * Just connection in SSL
       * call `conn_cb`, the ssl connection has been 
       *   established in user-land.
       */
      NET_LOG("net", "SSL Connection established");
      if (net->conn_cb != NULL) {
        net->conn_cb(net);
      }

    } else {
      /*
       * TODO(Yorkie): HOWTO
       */
    }
    return;
  }

  /*
   * TCP Part, no SSL, just proxy of uv.
   */
  uv_read_stop(handle);
  buf.base[nread] = 0;
  if (net->read_cb != NULL) {
    net->read_cb(net, nread, buf.base);
  }
}

int
net_write(net_t * net, char * buf) {
  int read = 0;

  switch (net->use_ssl) {
  case USE_SSL:
    tls_write(net->tls, buf);
    do {
      read = tls_bio_read(net->tls, 0);
      if (read > 0) {
        uv_buf_t uvbuf = uv_buf_init(net->tls->buf, read);
        uv_write(net->writer, (uv_stream_t*)net->handle, &uvbuf, 1, net_write_cb);
      }
    }
    while (read > 0);
    break;

  case NOT_SSL:
    read = strlen(buf);
    uv_buf_t uvbuf = uv_buf_init(buf, strlen(buf));
    uv_write(net->writer, (uv_stream_t*)net->handle, &uvbuf, 1, net_write_cb);
    break;
  };

  return OK;
}

int
net_use_ssl(net_t * net) {
  return net->use_ssl == USE_SSL;
}

int
net_resume(net_t * net) {
  uv_read_start((uv_stream_t *)net->handle, net_alloc, net_read);
  return OK;
}

void
net_write_cb(uv_write_t *writer, int stat) {
  net_t * net = (net_t *) writer->data;
  net_resume(net);
}