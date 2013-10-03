/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Sphynx nor the names of its contributors may be
	  used to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef CAT_SPHYNX_CLIENT_HPP
#define CAT_SPHYNX_CLIENT_HPP

#include "shorthair/Shorthair.hpp"
#include "cymric/Cymric.hpp"
#include "tabby/Tabby.hpp"

/*
 * Sphynx Network Client
 */

namespace cat {

namespace sphynx {


class Client : protected IShorthair {
public:
	struct Settings {
	};

	enum Reasons {
		DISCO_RESOLVE,	// Could not resolve hostname
	};

protected:
	bool _initialized;
	u16 _my_id;
	Settings _settings;
	u16 _port;
	struct sockaddr _server_addr;
	PublicKey _server_public_key;
	shorthair::Shorthair _sh;
	uv_loop_t _uv_loop;
	uv_udp_t _uv_udp;
	uv_timer_t _uv_hello;
	uv_timer_t _uv_tick;

	// Called with the latest data packet from remote host
	virtual void OnPacket(u8 *packet, int bytes) {
	}

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(u8 *packet, int bytes) {
	}

	// Send raw data to remote host over UDP socket
	virtual void SendData(u8 *buffer, int bytes) {
		CAT_ENFORCE(!uv_udp_send(uv_udp_send_t* req,
                          uv_udp_t* handle,
                          const uv_buf_t bufs[],
                          unsigned int nbufs,
                          const struct sockaddr* addr,
                          uv_udp_send_cb send_cb);
	}

	void OnConnect(const u8 *secret_key) {
		shorthair::Settings ss;
		ss.initiator = true;
		ss.target_loss = 0.0001;
		ss.min_loss = 0.03;
		ss.max_loss = 0.5;
		ss.min_delay = 100;
		ss.max_delay = 2000;
		ss.max_data_size = 1350;
		ss.interface = this;

		_sh.Initialize(secret_key, ss);
	}

	void SendHello() {
	}

	void Tick() {
		_sh.Tick();
	}

	// Called after a send completes
	static void uvOnSend(uv_udp_send_t *req, int status) {
	}

	static void uvOnRecv(uv_udp_t* handle,
			ssize_t nread,
			const uv_buf_t* buf,
			const struct sockaddr* addr,
			unsigned flags) {
	}

	static void uvAlloc(uv_handle_t* handle,
			size_t suggested_size,
			uv_buf_t* buf) {
	}

	static void uvHello(uv_timer_t *handle, int status) {
		Client *client = reinterpret_cast<Client *>( handle->data );

		client->SendHello();
	}

	static void uvTick(uv_timer_t *handle, int status) {
		Client *client = reinterpret_cast<Client *>( handle->data );

		client->Tick();
	}

	// Called after address resolution completes
	static void uvOnResolve(uv_getaddrinfo_t *handle, int status, struct addrinfo *response) {
		if (status == -1) {
			OnDisconnect(DISCO_RESOLVE);
		} else {
			_server_addr = response->ai_addr[0];

			CAT_ENFORCE(!uv_udp_bind(&_uv_udp, &_server_addr, 0));

			SendHello();

			CAT_ENFORCE(!uv_timer_init(&_uv_loop, &_uv_hello));

			CAT_ENFORCE(!uv_timer_start(&_uv_hello, callback, 200, 200));
		}

		uv_freeaddrinfo(response);
	}

public:
	CAT_INLINE Client() {
		_initialized = false;
	}
	CAT_INLINE virtual ~Client() {
		Finalize();
	}

	void Initialize(Settings &settings) {
		_settings = settings;
		_initialized = true;

		CAT_ENFORCE(!uv_udp_init(&_uv_loop, &_uv_udp));

		CAT_ENFORCE(!uv_udp_recv_start(&_uv_udp, uvAlloc, uvOnRecv));
	}

	void Finalize() {
		if (_initialized) {
			CAT_ENFORCE(!uv_udp_recv_stop(&_uv_udp));

			CAT_ENFORCE(!uv_timer_stop(&_uv_hello));
			CAT_ENFORCE(!uv_timer_stop(&_uv_tick));

			_initialized = false;
		}
	}

	void Connect(const char *host, u16 port, const PublicKey *key) {
		struct addrinfo hints;
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_flags = 0;

		uv_getaddrinfo_t *resolver = new uv_getaddrinfo_t;
		resolver->

    	int r = uv_getaddrinfo(loop, &resolver, on_resolved, "irc.freenode.net", "6667", &hints);
	}

	void Disconnect() {
	}

	virtual void OnConnect() {
	}

	virtual void OnDisconnect(int reason) {
	}
};


} // namespace sphynx

} // namespace cat

#endif // CAT_SPHYNX_CLIENT_HPP

