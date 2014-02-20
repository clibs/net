
#ifndef NET_TLS_H_
#define NET_TLS_H_

#include <openssl/ssl.h>
#include "buffer/buffer.h"

#define NOT_SSL 0x00
#define USE_SSL 0x01

typedef SSL_CTX tls_ctx;

typedef struct tls_s {
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *bio_in;
  BIO *bio_out;
  char buf[1024];
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
ssl_free();

/*
 * create a context for ssl
 */
tls_ctx *
tls_ctx_new();

/*
 * create a tls instance
 */
tls_t *
tls_create(tls_ctx*);

/*
 * destroy a tls instance
 */
int 
tls_free(tls_t*);

/*
 * do connect to tls
 */
int 
tls_connect(tls_t*);

/*
 * a port in tls for `bio_read`
 */
int 
tls_bio_read(tls_t*, int);

/*
 * a port in tls for `bio_write`
 */
int 
tls_bio_write(tls_t*, char*, int);

/*
 * read
 */
int 
tls_read(tls_t*);

/*
 * write
 */
int 
tls_write(tls_t*, char*);

#endif
/* ___TLS__ */