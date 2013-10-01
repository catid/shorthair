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

#include "Platform.hpp"
#include "snowshoe/Snowshoe.hpp"

namespace cat {

namespace tabby {


struct Hello {
	/*
	 * client -> server (102 bytes)
	 *
	 * The client sends this packet to request a connection.
	 *
	 * Schema:
	 *
	 * UID(2 bytes) = FFFFh
	 * Cookie(4 bytes) = 0 by default
	 * Client Public Key(64 bytes)
	 * Client Nonce(32 bytes)
	 */
	u8 data[2 + 4 + 64 + 32];
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
	u8 data[4];
};

struct Challenge {
	/*
	 * server -> client (109 bytes)
	 *
	 * The server responds with a Challenge to accept a connection request.
	 *
	 * Server Ephemeral Public Key(64 bytes)
	 * Server Nonce(32 bytes)
	 * Server Identity Proof(32 bytes)
	 * First Encrypted Data(2 bytes + 11 bytes overhead) = UID
	 */
	u8 data[64 + 32 + 32 + 11 + 2];
};


//// Server

class Server {
	PublicKey _public_key;
	cymric::Generator _generator;

public:
	Server() {
	}
	virtual ~Server() {
	}
};


//// Client

class Client {
	bool _initialized;
	u32 _client_private[8];
	u8 _client_nonce[32];
	ecpt _client_public, _server_public;
	cymric::Generator _generator;

public:
	Client() {
		_initialized = false;
	}
	virtual ~Client() {
		Finalize();
	}

	void Initialize(PublicKey &server_public_key);
	void Finalize();

	void FillHello(Hello *hello);
};


} // namespace tabby

} // namespace cat

#endif // CAT_TABBY_HPP


