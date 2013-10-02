/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Tabby nor the names of its contributors may be
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

#ifndef CAT_TABBY_HPP
#define CAT_TABBY_HPP

#include "cymric/Cymric.hpp"
#include "snowshoe/Snowshoe.hpp"
#include "calico/Calico.hpp"
#include "CookieJar.hpp"

/*
 * Tabby
 *
 * Key Agreement Protocol
 */

namespace cat {

namespace tabby {


static const int PRIVATE_KEY_SIZE = 32;
static const int PUBLIC_KEY_SIZE = 64;


struct Hello {
	/*
	 * client -> server (100 bytes)
	 *
	 * The client sends this packet to request a connection.
	 *
	 * Schema:
	 *
	 * Cookie(4 bytes) = 0 by default
	 * Client Public Key(64 bytes)
	 * Client Nonce(32 bytes)
	 */

	static const int COOKIE_SIZE = 4;
	static const int CLIENT_PUBLIC_KEY_SIZE = PUBLIC_KEY_SIZE;
	static const int CLIENT_NONCE_SIZE = 32;
	static const int HELLO_SIZE = COOKIE_SIZE + CLIENT_PUBLIC_KEY_SIZE + CLIENT_NONCE_SIZE;

	u8 data[HELLO_SIZE];
};

struct Cookie {
	/*
	 * server -> client (4 bytes)
	 *
	 * The server responds with a Cookie if it is under load and would like to
	 * reduce the impact of a potential DoS attack by insuring that connections
	 * originate from actual clients.
	 *
	 * Schema:
	 *
	 * Cookie(4 bytes)
	 */

	static const int COOKIE_SIZE = 4;

	u8 data[COOKIE_SIZE];
};

struct Answer {
	/*
	 * server -> client (128 bytes)
	 *
	 * The server responds with an Answer to accept a connection request.
	 *
	 * Server Ephemeral Public Key(64 bytes)
	 * Server Nonce(32 bytes)
	 * Server Identity Proof(32 bytes)
	 */

	static const int EPHEMERAL_PUBLIC_KEY_SIZE = PUBLIC_KEY_SIZE;
	static const int SERVER_NONCE_SIZE = 32;
	static const int SERVER_IDENTITY_SIZE = 32;
	static const int ANSWER_SIZE = EPHEMERAL_PUBLIC_KEY_SIZE + SERVER_NONCE_SIZE + SERVER_IDENTITY_SIZE;

	u8 data[ANSWER_SIZE];
};


//// Server

class Server {
public:
	static const int CLIENT_PRIVATE_WORDS = 8;

protected:
	bool _initialized;
	CookieJar _jar;
	ecpt _ephemeral_public;
	u8 _server_public_data[PUBLIC_KEY_SIZE];
	dude _server_private, _ephemeral_private;
	cymric::Cymric _generator;
	// TODO: Periodically change the ephemeral private/public key

	void GenerateEphemeralKey();

public:
	CAT_INLINE Server() {
		_initialized = false;
	}
	CAT_INLINE virtual ~Server() {
		Finalize();
	}

	void Initialize(const u8 server_public_key[PUBLIC_KEY_SIZE], const u8 server_private_key[PRIVATE_KEY_SIZE]);
	void Finalize();

	void FillCookie(const void *addr, int len, Cookie *cookie);

	// Returns false if Hello is invalid
	bool FillAnswer(const void *addr, int len, const Hello *hello, Answer *answer, u8 secret_key[PRIVATE_KEY_SIZE]);
};


//// Client

class Client {
public:
	static const int CLIENT_PRIVATE_WORDS = 8;

protected:
	bool _initialized;
	u32 _last_cookie;
	u32 _client_private[CLIENT_PRIVATE_WORDS];
	u8 _client_nonce[Hello::CLIENT_NONCE_SIZE];
	ecpt _client_public, _server_public;
	cymric::Cymric _generator;

public:
	CAT_INLINE Client() {
		_initialized = false;
	}
	CAT_INLINE virtual ~Client() {
		Finalize();
	}

	void Initialize(const u8 server_public_key[PUBLIC_KEY_SIZE]);
	void Finalize();

	void FillHello(Hello *hello);

	bool ReadAnswer(Answer *answer, u8 secret_key[PRIVATE_KEY_SIZE]);
};


} // namespace tabby

} // namespace cat

#endif // CAT_TABBY_HPP

