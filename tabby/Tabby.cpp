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
using namespace cat;
using namespace tabby;
using namespace snowshoe;


//// Client

void Client::Initialize(PublicKey &server_public_key) {
	Finalize();

	_server_public_key = server_public_key;

	_generator.Initialize();

	_generator.Generate(_client_private, sizeof(_client_private));
	_generator.Generate(_client_nonce, sizeof(_client_nonce));

	Snowshoe::MulG(_client_private, _client_public);

	_initialized = true;
}

void Client::FillHello(Hello *hello) {
	//hello->data;
}

void Client::Finalize() {
	if (_initialized) {
		CAT_SECURE_CLR(_client_private, sizeof(_client_private));
		CAT_SECURE_CLR(_client_nonce, sizeof(_client_nonce));
		CAT_SECURE_CLR(_client_public, sizeof(_client_public));
		CAT_SECURE_CLR(_server_public, sizeof(_server_public));

		_initialized = false;
	}
}

