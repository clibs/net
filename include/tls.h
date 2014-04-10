
/*
 * Copyright 2014 <yorkiefixer@gmail.com>
 */

#pragma once

#include <openssl/ssl.h>
#include <buffer/buffer.h>

#define NOT_SSL 0x00
#define USE_SSL 0x01

typedef SSL_CTX tls_ctx;

typedef struct tls_s {
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *bio_in;
  BIO *bio_out;
  int connected;
  char buf[4086];
  char *data;
  buffer_t *buffer;
} tls_t;

/*
 * initialize the ssl
 */
void
ssl_init();

/*
 * destroy the ssl settings and internal tables
 */
void
ssl_destroy();

/*
 * create a context for ssl
 */
tls_ctx *
tls_ctx_new();

/*
 * create a tls instance
 */
tls_t *
tls_create(tls_ctx * ctx);

/*
 * destroy a tls instance
 */
int
tls_free(tls_t * tls);

/*
 * do connect to tls
 */
int
tls_connect(tls_t * tls);

/*
 * a port in tls for `bio_read`
 */
int
tls_bio_read(tls_t * tls, int len);

/*
 * a port in tls for `bio_write`
 */
int
tls_bio_write(tls_t * tls, char * written, int len);

/*
 * read
 */
int
tls_read(tls_t * tls);

/*
 * write
 */
int
tls_write(tls_t * tls, char * written, int len);

/*
 * write a tls packet
 */
#define REQUEST_TLS_WRITE(name, cmd, read, req) do {                   \
  tls_write(req->tls, cmd);                                            \
  do {                                                                    \
    read = tls_bio_read(req->tls, 0);                                  \
    if (read > 0) {                                                       \
      REQUEST_WRITE(req, req->tls->buf, read, name);                   \
    }                                                                     \
  } while (read > 0);                                                     \
}                                                                         \
while (0)