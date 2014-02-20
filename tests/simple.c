
/*
 * TODO(Yorkie): Expected to be add a graceful test
 *
 */

#include <stdio.h>
#include <assert.h>
#include "net.h"
#include "tls.h"
#include "uv.h"

static void 
read_cb(net_t * net, size_t read, char * buf) {
  printf("%s\n", buf);
  printf("%zu\n", read);
}

int
main(int argc, char ** argv) {

  ssl_init();
  tls_ctx * ctx = tls_ctx_new();
  net_t * net = net_new("imap.gmail.com", 993);
  net->read_cb = read_cb;

  net_set_tls(net, ctx);
  net_connect(net);

  /* without ssl */
  net_t * net_ = net_new("imap.qq.com", 143);
  net_->read_cb = read_cb;
  net_connect(net_);

  uv_run(net->loop, UV_RUN_DEFAULT);
  return 0;
}