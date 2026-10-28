/* TLS client (static OpenSSL) on Deloxy: DNS via the kernel resolver, TCP, full certificate + hostname verification. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include "tls/ca_pem.h"
static int connect_to(const char *host, const char *port) {
  struct addrinfo h = {0}, *r; h.ai_family = AF_INET; h.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &h, &r)) return -1;
  int s = socket(AF_INET, SOCK_STREAM, 0); if (connect(s, r->ai_addr, r->ai_addrlen)) { close(s); return -1; }
  freeaddrinfo(r); return s;
}
static int attempt(const char *connect_name, const char *verify_name, int use_ca) {
  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  if (use_ca) {
    BIO *b = BIO_new_mem_buf(CA_PEM, -1); X509 *ca = PEM_read_bio_X509(b, 0, 0, 0); X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), ca); X509_free(ca); BIO_free(b);
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  int s = connect_to(connect_name, "8443"); if (s < 0) { printf("tls: connect failed\n"); return -1; }
  SSL *ssl = SSL_new(ctx); SSL_set_fd(ssl, s); SSL_set1_host(ssl, verify_name); SSL_set_tlsext_host_name(ssl, verify_name);
  int rc = SSL_connect(ssl);
  if (rc != 1) { printf("tls: handshake REJECTED (%s)\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl))); SSL_free(ssl); close(s); SSL_CTX_free(ctx); return 1; }
  printf("tls: handshake OK %s %s verify=%s\n", SSL_get_version(ssl), SSL_get_cipher_name(ssl), X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
  const char *rq = "GET /hello HTTP/1.0\r\nHost: mock.deloxy.test\r\n\r\n"; SSL_write(ssl, rq, strlen(rq));
  char buf[1024]; int n, tot = 0; while (tot < (int)sizeof buf - 1 && (n = SSL_read(ssl, buf + tot, sizeof buf - 1 - tot)) > 0) tot += n;
  buf[tot] = 0; char *body = strstr(buf, "\r\n\r\n"); printf("tls: response body '%s'\n", body ? body + 4 : buf);
  SSL_shutdown(ssl); SSL_free(ssl); close(s); SSL_CTX_free(ctx); return 0;
}
int main(void) {
  attempt("mock.deloxy.test", "mock.deloxy.test", 1);        /* trusted CA, right name  -> OK       */
  attempt("mock.deloxy.test", "other.example.com", 1);       /* right CA, wrong name    -> rejected */
  attempt("mock.deloxy.test", "mock.deloxy.test", 0);        /* unknown CA              -> rejected */
  printf("tls: done\n"); return 0;
}
