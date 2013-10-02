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

#include "Tabby.hpp"
#include "calico/Skein.hpp"
using namespace cat;
using namespace tabby;
using namespace snowshoe;


//// Server

void Server::Initialize(const u8 server_public_key[PUBLIC_KEY_SIZE], const u8 server_private_key[PRIVATE_KEY_SIZE]) {
	CAT_ENFORCE(server_public_key && server_private_key);

	Snowshoe::Unpack(server_public_key, _server_public);
	memcpy(_server_private_key, server_private_key, PRIVATE_KEY_SIZE);

	_generator.Initialize();

	_jar.Initialize(_generator);

	GenerateEphemeralKey();

	// TODO: Clean up what data is actually needed, validate input

	_initialized = true;
}

void Server::Finalize() {
	if (_initialized) {
		CAT_SECURE_CLR(_server_private, PRIVATE_KEY_SIZE);
		CAT_SECURE_CLR(_ephemeral_private, PRIVATE_KEY_SIZE);

		_initialized = false;
	}
}

void Server::GenerateEphemeralKey() {
	u8 ephemeral_private[PRIVATE_KEY_SIZE];
	ecpt ephemeral_public;

	_generator.Generate(ephemeral_private, PRIVATE_KEY_SIZE);
	Snowshoe::MulG(ephemeral_private, ephemeral_public);

	// TODO: Lock

	memcpy(_ephemeral_private, ephemeral_private, PRIVATE_KEY_SIZE);
	memcpy(_ephemeral_public, ephemeral_public, PUBLIC_KEY_SIZE);

	// TODO: Unlock

	CAT_SECURE_CLR(ephemeral_private, PRIVATE_KEY_SIZE);
}

void Server::FillCookie(const void *addr, int len, Cookie *cookie) {
	CAT_ENFORCE(addr && len > 0 && cookie);

	u32 *cookieWord = reinterpret_cast<u32 *>( cookie->data );

	*cookieWord = _jar.Generate(addr, len); // No need to fix byte order
}

bool Server::FillAnswer(const void *addr, int len, const Hello *hello, Answer *answer, u8 secret_key[PRIVATE_KEY_SIZE]) {
	CAT_ENFORCE(hello && id && answer && secret_key);

	// Input:
	const u32 *cookie = reinterpret_cast<u32 *>( hello->data );
	const u8 *client_public_key_data = hello->data + Hello::COOKIE_SIZE;
	const u8 *client_nonce = client_public_key + PUBLIC_KEY_SIZE;

	// If cookie is invalid,
	if (!_jar.Verify(addr, len, *cookie)) {
		// Reject the Hello
		return false;
	}

	// Unpack the client public key
	ecpt client_public;
	Snowshoe::Unpack(client_public_data, client_public);

	// If input public point is invalid,
	if (!Snowshoe::Scrub(client_public)) {
		// Reject the Hello
		return false;
	}

	// Output:
	u8 *ephemeral_public_data = answer->data;
	u8 *server_nonce = ephemeral_public + PUBLIC_KEY_SIZE;
	u8 *server_proof = server_nonce + Answer::SERVER_NONCE_SIZE;

	// Copy ephemeral public key over
	Snowshoe::Pack(_ephemeral_public, ephemeral_public_data);

	// Generate a nonce
	_generator.Generate(server_nonce, Answer::SERVER_NONCE_SIZE);

	Skein key_hash;
	u8 d_data[Snowshoe::SCALAR_BYTES];
	dude d;

	do {
		CAT_ENFORCE(key_hash.BeginKey(256));
		CAT_ENFORCE(key_hash.BeginKDF());
		key_hash.Crunch(client_public_data, PUBLIC_KEY_SIZE);
		key_hash.Crunch(_server_public_data, PUBLIC_KEY_SIZE);
		key_hash.Crunch(ephemeral_public_data, PUBLIC_KEY_SIZE);
		key_hash.Crunch(client_nonce, Hello::CLIENT_NONCE_SIZE);
		key_hash.Crunch(server_nonce, Answer::SERVER_NONCE_SIZE);
		key_hash.End();
		key_hash.Generate(d_data, Snowshoe::SCALAR_BYTES);

		dude_unpack(d_data, d);
	} while (dude_less(d, 1000));

	// Calculate d = (long-term server private key) + d * (ephemeral private key) (mod q)
	dude_mul(d, _ephemeral_private, d);
	dude_add(d, _server_private, d);
	dude_pack(d, d_data);

	// Calculate (private point) = d * (client public point)
	ecpt private_point;
	Snowshoe::Mul(d, client_public, private_point);
	Snowshoe::Affine(private_point);

	u8 private_point_data[Snowshow::POINT_BYTES];
	Snowshoe::Pack(private_point, private_point_data);

	// Calculate (secret key) = H(d, (private point), (client nonce), (server nonce))
	CAT_ENFORCE(key_hash.BeginKey(256));
	CAT_ENFORCE(key_hash.BeginKDF());
	key_hash.Crunch(d_data, Snowshow::SCALAR_BYTES);
	key_hash.Crunch(private_point_data, Snowshow::POINT_BYTES);
	key_hash.Crunch(client_nonce, Hello::CLIENT_NONCE_SIZE);
	key_hash.Crunch(server_nonce, Answer::SERVER_NONCE_SIZE);
	key_hash.End();
	key_hash.Generate(secret_key, PRIVATE_KEY_SIZE);

	// Generate server identity field
	key_hash.Generate(server_proof, Answer::SERVER_IDENTITY_SIZE);

	// TODO: Secure erase private keys

	return true;
}


//// Client

bool Client::Initialize(const u8 server_public_data[PUBLIC_KEY_SIZE]) {
	CAT_ENFORCE(server_public_key);

	Finalize();

	Snowshoe::Unpack(server_public_data, _server_public);

	// If server key is invalid,
	if (!Snowshoe::Scrub(_server_public)) {
		// Fail initialization
		return false;
	}

	_generator.Initialize();

	_generator.Generate(_client_private, sizeof(_client_private));
	_generator.Generate(_client_nonce, sizeof(_client_nonce));

	Snowshoe::MulG(_client_private, _client_public);

	_initialized = true;

	return true;
}

void Client::Finalize() {
	if (_initialized) {
		CAT_SECURE_CLR(_client_private, PRIVATE_KEY_SIZE);

		_initialized = false;
	}
}

void Client::FillHello(Hello *hello) {
	CAT_ENFORCE(hello);

	u16 *id = reinterpret_cast<u16 *>( hello->data );
	u32 *cookie = reinterpret_cast<u32 *>( hello->data + Hello::UID_SIZE );
	u8 *client_public_key = hello->data + Hello::UID_SIZE + Hello::COOKIE_SIZE;
	u8 *client_nonce = client_public_key + Hello::CLIENT_PUBLIC_KEY_SIZE;

	*id = 0; // 0 = Connection request
	*cookie = getLE(_last_cookie);
	Snowshoe::Pack(_client_public, client_public_key);
	memcpy(_client_nonce, client_nonce, CLIENT_NONCE_SIZE);
}

bool Client::ReadAnswer(const Answer *answer, u8 secret_key[PRIVATE_KEY_SIZE]) {
	const u8 *ephemeral_public_data = answer->data;
	const u8 *server_nonce = ephemeral_public + PUBLIC_KEY_SIZE;
	const u8 *server_proof = server_nonce + Answer::SERVER_NONCE_SIZE;

	// Read ephemeral public key
	ecpt ephemeral_public;
	Snowshoe::Unpack(ephemeral_public_data, ephemeral_public);

	// If ephemeral key is bad,
	if (!Snowshoe::Scrub(ephemeral_public)) {
		// Reject answer
		return false;
	}

	u8 d_data[Snowshoe::SCALAR_BYTES];
	dude d;

	Skein key_hash;
	CAT_ENFORCE(key_hash.BeginKey(256));
	CAT_ENFORCE(key_hash.BeginKDF());
	key_hash.Crunch(_client_public_data, PUBLIC_KEY_SIZE);
	key_hash.Crunch(_server_public_data, PUBLIC_KEY_SIZE);
	key_hash.Crunch(ephemeral_public_data, PUBLIC_KEY_SIZE);
	key_hash.Crunch(_client_nonce, Hello::CLIENT_NONCE_SIZE);
	key_hash.Crunch(server_nonce, Answer::SERVER_NONCE_SIZE);
	key_hash.End();
	key_hash.Generate(d_data, Snowshoe::SCALAR_BYTES);

	dude_unpack(d_data, d);

	// If d is invalid,
	if (dude_less(d, 1000)) {
		// Reject answer
		return false;
	}

	// Calculate d = d * a
	dude d;
	dude_mul(d, _client_private, d);

	// Calculate (private point) = d * (ephemeral public) + (client private) * (server public)
	ecpt private_point;
	Snowshoe::SiMul(d, ephemeral_public, _client_private, _server_public, private_point);
	Snowshoe::Affine(private_point);

	u8 private_point_data[Snowshow::POINT_BYTES];
	Snowshoe::Pack(private_point, private_point_data);

	// Calculate (secret key) = H(d, (private point), (client nonce), (server nonce))
	CAT_ENFORCE(key_hash.BeginKey(256));
	CAT_ENFORCE(key_hash.BeginKDF());
	key_hash.Crunch(d_data, Snowshow::SCALAR_BYTES);
	key_hash.Crunch(private_point_data, Snowshow::POINT_BYTES);
	key_hash.Crunch(client_nonce, Hello::CLIENT_NONCE_SIZE);
	key_hash.Crunch(server_nonce, Answer::SERVER_NONCE_SIZE);
	key_hash.End();
	key_hash.Generate(secret_key, PRIVATE_KEY_SIZE);

	// Generate server identity field
	key_hash.Generate(server_proof, Answer::SERVER_IDENTITY_SIZE);

	// TODO: Secure erase private keys

	return true;
}

