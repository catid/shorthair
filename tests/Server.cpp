#include <uv.h>
#include "shorthair/ShorthairAPI.h"

#include "Enforcer.hpp"
using namespace cat;

#include <iostream>
#include <cstdio>
#include <cstdlib>
using namespace std;


typedef struct {
  uv_write_t req;
  uv_buf_t buf;
} write_req_t;

static int server_closed = 0;
static uv_udp_t udpServer;

static void after_write(uv_write_t* req, int status);
static void after_read(uv_stream_t*, ssize_t nread, const uv_buf_t* buf);
static void on_close(uv_handle_t* peer);
static void on_server_close(uv_handle_t* handle);
static void on_connection(uv_stream_t*, int status);


static void after_write(uv_write_t* req, int status) {
	write_req_t* wr;

	/* Free the read/write buffer and the request */
	wr = (write_req_t*) req;
	free(wr->buf.base);
	free(wr);

	if (status == 0)
		return;

	cout << "UV WRITE ERROR" << endl;

	if (status == UV_ECANCELED)
		return;

	CAT_ENFORCE(status == UV_EPIPE);
	uv_close((uv_handle_t*)req->handle, on_close);
}


static void after_shutdown(uv_shutdown_t* req, int status) {
	uv_close((uv_handle_t*)req->handle, on_close);
	free(req);
}


static void after_read(uv_stream_t* handle,
		ssize_t nread,
		const uv_buf_t* buf) {
	int i;
	write_req_t *wr;
	uv_shutdown_t* req;

	if (nread < 0) {
		/* Error or EOF */
		CAT_ENFORCE(nread == UV_EOF);

		if (buf->base) {
			free(buf->base);
		}

		req = (uv_shutdown_t*) malloc(sizeof *req);
		uv_shutdown(req, handle, after_shutdown);

		return;
	}

	if (nread == 0) {
		/* Everything OK, but nothing read. */
		free(buf->base);
		return;
	}

	/*
	 * Scan for the letter Q which signals that we should quit the server.
	 * If we get QS it means close the stream.
	 */
	if (!server_closed) {
		for (i = 0; i < nread; i++) {
			if (buf->base[i] == 'Q') {
				if (i + 1 < nread && buf->base[i + 1] == 'S') {
					free(buf->base);
					uv_close((uv_handle_t*)handle, on_close);
					return;
				} else {
					uv_close((uv_handle_t*)&udpServer, on_server_close);
					server_closed = 1;
				}
			}
		}
	}

	wr = (write_req_t*) malloc(sizeof *wr);

	wr->buf = uv_buf_init(buf->base, nread);
	if (uv_write(&wr->req, handle, &wr->buf, 1, after_write)) {
		cout << "uv_write failed" << endl;
	}
}


static void on_close(uv_handle_t* peer) {
	free(peer);
}


static uv_buf_t echo_alloc(uv_handle_t* handle,
		size_t suggested_size) {
	uv_buf_t buf;

	buf.base = (char*)malloc(suggested_size);
	buf.len = suggested_size;

	return buf;
}


static void on_server_close(uv_handle_t* handle) {
	CAT_ENFORCE(handle == (uv_handle_t*)&udpServer);
}


static void on_send(uv_udp_send_t* req, int status) {
	CAT_ENFORCE(status == 0);
	free(req);
}

static void on_recv(uv_udp_t* handle,
		ssize_t nread,
		uv_buf_t rcvbuf,
		struct sockaddr* addr,
		unsigned flags) {
	uv_udp_send_t* req;
	uv_buf_t sndbuf;

	CAT_ENFORCE(nread > 0);
	CAT_ENFORCE(addr->sa_family == AF_INET);

	req = (uv_udp_send_t*)malloc(sizeof(*req));
	CAT_ENFORCE(req != NULL);

	sndbuf = rcvbuf;
	CAT_ENFORCE(!uv_udp_send(req, handle, &sndbuf, 1, *(struct sockaddr_in*)addr, on_send));
}


int main() {
	cout << "Demo Server" << endl;

	uv_loop_t *loop = uv_default_loop();

	int r;

	struct sockaddr_in addr = uv_ip4_addr("0.0.0.0", 5656);

	CAT_ENFORCE(!uv_udp_init(loop, &udpServer));

	CAT_ENFORCE(!uv_udp_bind(&udpServer, addr, 0));

	CAT_ENFORCE(!uv_udp_recv_start(&udpServer, echo_alloc, on_recv));

	uv_run(loop, UV_RUN_DEFAULT);

	return 0;
}

