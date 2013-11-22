/*
	Copyright (c) 2009-2011 Christopher A. Taylor.	All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of LibCat nor the names of its contributors may be used
	  to endorse or promote products derived from this software without
	  specific prior written permission.

	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
	AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
	IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
	ARE DISCLAIMED.	 IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
	LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
	CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
	SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
	CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
	ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
	POSSIBILITY OF SUCH DAMAGE.
*/

#include "Skein.hpp"
#include "EndianNeutral.hpp"
using namespace cat;

Skein::~Skein()
{
	CAT_SECURE_OBJCLR(State);
	CAT_SECURE_OBJCLR(Tweak);
	CAT_SECURE_OBJCLR(Work);
}

void Skein::GenerateInitialState(int bits)
{
	u64 w[MAX_WORDS] = { getLE64(SCHEMA_VER), getLE64(bits), 0 };

	CAT_OBJCLR(State);

	// T1 = FIRST | FINAL | CFG
	Tweak[0] = 0;
	Tweak[1] = T1_MASK_FIRST | T1_MASK_FINAL | ((u64)BLK_TYPE_CFG << T1_POS_BLK_TYPE);

	(this->*hash_func)(w, 1, 32, State);
}

// Cached copies of initial state for different bit lengths
static const u64 State0_160[4] = {
	0x1420231472825e98ULL, 0x2ac4e9a25a77e590ULL, 0xd47a58568838d63eULL, 0x2dd2e4968586ab7dULL
};

static const u64 State0_224[4] = {
	0xc6098a8c9ae5ea0bULL, 0x876d568608c5191cULL, 0x99cb88d7d7f53884ULL, 0x384bddb1aeddb5deULL
};

static const u64 State0_256[4] = {
	0xfc9da860d048b449ULL, 0x2fca66479fa7d833ULL, 0xb33bc3896656840fULL, 0x6a54e920fde8da69ULL
};

static const u64 State0_384[8] = {
	0xa3f6c6bf3a75ef5fULL, 0xb0fef9ccfd84faa4ULL, 0x9d77dd663d770cfeULL, 0xd798cbf3b468fddaULL,
	0x1bc4a6668a0e4465ULL, 0x7ed7d434e5807407ULL, 0x548fc1acd4ec44d6ULL, 0x266e17546aa18ff8ULL
};

static const u64 State0_512[8] = {
	0x4903adff749c51ceULL, 0x0d95de399746df03ULL, 0x8fd1934127c79bceULL, 0x9a255629ff352cb1ULL,
	0x5db62599df6ca7b0ULL, 0xeabe394ca9d5c3f4ULL, 0x991112c71a75b523ULL, 0xae18a40b660fcc33ULL
};

bool Skein::BeginKey(int bits)
{
	if (bits <= 256) {
		digest_bytes = 256 / 8;
		digest_bytes_shift = 5;
		digest_words = 256 / 64;
		hash_func = &Skein::HashComputation256;
	} else return false;

	// Try to use a cached copy of the initial state
	switch (bits)
	{
	case 160: memcpy(State, State0_160, sizeof(State0_160)); break;
	case 224: memcpy(State, State0_224, sizeof(State0_224)); break;
	case 256: memcpy(State, State0_256, sizeof(State0_256)); break;
	default: GenerateInitialState(bits);
	}

	// T1 = FIRST | KEY
	Tweak[0] = 0;
	Tweak[1] = T1_MASK_FIRST | ((u64)BLK_TYPE_KEY << T1_POS_BLK_TYPE);

	used_bytes = 0;
	output_prng_mode = false;

	return true;
}

bool Skein::SetKey(ICryptHash *key_hash)
{
	const Skein *parent = static_cast<const Skein *>(key_hash);
	if (!parent) return false;

	memcpy(State, parent->State, sizeof(State));
	digest_bytes = parent->digest_bytes;
	digest_words = parent->digest_words;
	hash_func = parent->hash_func;

	// The user will then call one of the Begin() functions below:

	return true;
}

bool Skein::BeginMAC()
{
	// T1 = FIRST | MSG
	Tweak[0] = 0;
	Tweak[1] = T1_MASK_FIRST | ((u64)BLK_TYPE_MSG << T1_POS_BLK_TYPE);

	used_bytes = 0;
	output_prng_mode = false;

	return true;
}

bool Skein::BeginKDF()
{
	// T1 = FIRST | KDF
	Tweak[0] = 0;
	Tweak[1] = T1_MASK_FIRST | ((u64)BLK_TYPE_KDF << T1_POS_BLK_TYPE);

	used_bytes = 0;
	output_prng_mode = false;

	return true;
}

bool Skein::BeginPRNG()
{
	// T1 = FIRST | NONCE
	Tweak[0] = 0;
	Tweak[1] = T1_MASK_FIRST | ((u64)BLK_TYPE_NONCE << T1_POS_BLK_TYPE);

	used_bytes = 0;
	output_prng_mode = true;

	return true;
}

void Skein::Crunch(const void *_message, int bytes)
{
	const u8 *buffer = (const u8*)_message;

	// If there are bytes left to hash from last time,
	if (used_bytes)
	{
		// If we still cannot overflow the workspace,
		if (used_bytes + bytes <= digest_bytes)
		{
			// Just append the new message bytes
			memcpy(Work + used_bytes, buffer, bytes);
			used_bytes += bytes;
			return;
		}

		// Fill the rest of the workspace
		u32 copied = digest_bytes - used_bytes;

		memcpy(Work + used_bytes, buffer, copied);

		(this->*hash_func)(Work, 1, digest_bytes, State);

		// Eat those bytes of the message
		bytes -= copied;
		buffer += copied;
	}

	// If the remaining bytes of the message overflows the workspace,
	if (bytes > digest_bytes)
	{
		// Hash whole digest blocks at a time
		int eat_bytes = bytes - 1;

		// Hash directly from the message
		u32 hash_blocks = eat_bytes >> digest_bytes_shift;
		u32 block_bytes = hash_blocks << digest_bytes_shift;
		(this->*hash_func)(buffer, hash_blocks, block_bytes, State);

		// Eat those bytes of the message
		eat_bytes &= ~(digest_bytes-1);
		buffer += eat_bytes;
		bytes -= eat_bytes;
	}

	// Copy what remains into the workspace
	memcpy(Work, buffer, bytes);
	used_bytes = bytes;
}

void Skein::End()
{
	// NOTE: We should always have at least one message hash to perform here

	// Pad with zeroes
	CAT_CLR(Work + used_bytes, digest_bytes - used_bytes);

	// Final message hash
	Tweak[1] |= T1_MASK_FINAL;
	(this->*hash_func)(Work, 1, used_bytes, State);

	output_block_counter = 0;
}

void Skein::Generate(void *out, int bytes, int strengthening_rounds)
{
	// Put the Skein generator in counter mode and generate WORDS at a time
	u64 NextState[MAX_WORDS];
	u64 FinalMessage[MAX_WORDS] = {output_block_counter, 0};
	u64 *out64 = (u64 *)out;

	// In strengthened mode, discard a number of rounds before producing real output
	while (strengthening_rounds-- >= 1)
	{
		// T1 = FIRST | FINAL | OUT
		Tweak[0] = 0;
		Tweak[1] = T1_MASK_FIRST | T1_MASK_FINAL | ((u64)BLK_TYPE_OUT << T1_POS_BLK_TYPE);

		// Produce next output
		(this->*hash_func)(FinalMessage, 1, 8, NextState);

		// Next counter
		FinalMessage[0] = ++output_block_counter;
	}

	// In output mode, we hide the first block of each request
	if (output_prng_mode)
	{
		// T1 = FIRST | FINAL | OUT
		Tweak[0] = 0;
		Tweak[1] = T1_MASK_FIRST | T1_MASK_FINAL | ((u64)BLK_TYPE_OUT << T1_POS_BLK_TYPE);

		// Produce next output
		(this->*hash_func)(FinalMessage, 1, 8, NextState);

		// Next counter
		FinalMessage[0] = ++output_block_counter;
	}

	while (bytes >= digest_bytes)
	{
		// T1 = FIRST | FINAL | OUT
		Tweak[0] = 0;
		Tweak[1] = T1_MASK_FIRST | T1_MASK_FINAL | ((u64)BLK_TYPE_OUT << T1_POS_BLK_TYPE);

		// Produce next output
		(this->*hash_func)(FinalMessage, 1, 8, out64);

		for (int ii = 0; ii < digest_words; ++ii)
			swapLE(out64[ii]);

		// Next counter
		out64 += digest_words;
		bytes -= digest_bytes;
		FinalMessage[0] = ++output_block_counter;
	}

	if (bytes > 0)
	{
		// T1 = FIRST | FINAL | OUT
		Tweak[0] = 0;
		Tweak[1] = T1_MASK_FIRST | T1_MASK_FINAL | ((u64)BLK_TYPE_OUT << T1_POS_BLK_TYPE);

		// Produce final output
		(this->*hash_func)(FinalMessage, 1, 8, FinalMessage);

		for (int ii = CAT_CEIL_UNIT(bytes, sizeof(u64)); ii >= 0; --ii)
			swapLE(FinalMessage[ii]);

		// Copy however many bytes they wanted
		memcpy(out64, FinalMessage, bytes);

		++output_block_counter;
	}

	// In PRNG output mode, use the first hidden output block as the next state
	if (output_prng_mode)
		memcpy(State, NextState, digest_bytes);
}
