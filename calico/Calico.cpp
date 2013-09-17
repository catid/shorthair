#include "Calico.hpp"
#include "Skein.hpp"
#include "EndianNeutral.hpp"
#include "BitMath.hpp"
using namespace cat;
using namespace calico;

#include <climits>

// IV constants
static const int IV_BYTES = 3;
static const int IV_BITS = IV_BYTES * 8;
static const u32 IV_MSB = (1 << IV_BITS);
static const u32 IV_MASK = (IV_MSB - 1);
static const u32 IV_FUZZ = 0x9F286AD7;


//// Calico

const char *Calico::GetErrorString(int error_code)
{
	if (error_code >= ERR_GROOVY)
		return "No error";

	switch (error_code)
	{
	case ERR_BAD_STATE: return "Bad state";
	case ERR_BAD_INPUT: return "Bad input";
	case ERR_INTERNAL:	return "Internal error";
	case ERR_TOO_SMALL: return "Too small";
	case ERR_IV_DROP:	return "IV-based drop";
	case ERR_MAC_DROP:	return "MAC-based drop";
	default:			return "Unknown";
	}
}

Calico::Calico()
{
	_initialized = false;
}

int Calico::Initialize(const void *key,				// Pointer to key material
					   const char *session_name,	// Unique session name
					   int mode)					// Value from CalicoModes
{
	_initialized = false;

	if (!key || !session_name)
		return ERR_BAD_INPUT;
	if (mode < INITIATOR || mode > RESPONDER)
		return ERR_BAD_INPUT;

	Skein key_hash, kdf;

	// Initialize the key from the input key and the session name
	if (!key_hash.BeginKey(256)) return ERR_INTERNAL;
	if (!key_hash.BeginKDF()) return ERR_INTERNAL;
	key_hash.Crunch(key, 32);
	key_hash.CrunchString(session_name);
	key_hash.End();

	// Generate subkeys using KDF mode of Skein
	u8 keys[200 + 200];
	key_hash.Generate(keys, (int)sizeof(keys));

	// Swap keys based on mode
	u8 *lkey = keys, *rkey = keys;
	if (mode == INITIATOR) lkey += 200;
	else rkey += 200;

	// Initialize the cipher with these keys
	_cipher.Initialize(lkey, rkey);

	// Grab the IVs from the key bytes
	u64 liv = getLE(*(u64*)(lkey + 192));
	u64 riv = getLE(*(u64*)(rkey + 192));

	// Initialize the IV subsystem
	_window.Initialize(liv, riv);

	_initialized = true;

	CAT_SECURE_OBJCLR(keys);

	return ERR_GROOVY;
}

int Calico::Encrypt(const void *plaintext,	// Pointer to input plaintext
					int plaintext_bytes, 	// Input buffer size
					void *ciphertext,		// Pointer to output ciphertext
					int ciphertext_bytes)	// Output buffer size
{
	if (!_initialized)
		return ERR_BAD_STATE;
	if (!plaintext || plaintext_bytes < 0 || !ciphertext)
		return ERR_BAD_INPUT;
	if (plaintext_bytes > INT_MAX - OVERHEAD)
		return ERR_TOO_SMALL;
	if (plaintext_bytes + OVERHEAD > ciphertext_bytes)
		return ERR_TOO_SMALL;

	// Get next outgoing IV
	u64 iv = _window.NextLocal();

	// Encrypt data and slap on a MAC
	_cipher.Encrypt(iv, plaintext, ciphertext, plaintext_bytes);

	u8 *overhead8 = reinterpret_cast<u8*>( ciphertext ) + plaintext_bytes;
	const u32 *overhead32 = reinterpret_cast<const u32*>( overhead8 );

	// Obfuscate the truncated IV
	u32 trunc_iv = (u32)iv;
	trunc_iv -= getLE(*overhead32);
	trunc_iv ^= IV_FUZZ;

	// Append it to the data
	overhead8[8] = (u8)trunc_iv;
	overhead8[9] = (u8)(trunc_iv >> 16);
	overhead8[10] = (u8)(trunc_iv >> 8);

	return plaintext_bytes + OVERHEAD;
}

int Calico::Decrypt(void *ciphertext,		// Pointer to ciphertext
					int ciphertext_bytes)	// Number of valid encrypted data bytes
{
	if (!_initialized)
		return ERR_BAD_STATE;
	if (!ciphertext)
		return ERR_BAD_INPUT;
	if (ciphertext_bytes < INT_MIN + OVERHEAD)
		return ERR_TOO_SMALL;

	int plaintext_bytes = ciphertext_bytes - OVERHEAD;
	if (plaintext_bytes < 0)
		return ERR_TOO_SMALL;

	u8 *overhead8 = reinterpret_cast<u8*>( ciphertext ) + plaintext_bytes;
	u32 *overhead32 = reinterpret_cast<u32*>( overhead8 );

	// Grab the obfuscated IV
	u32 trunc_iv = ((u32)overhead8[10] << 8) | ((u32)overhead8[9] << 16) | (u32)overhead8[8];

	// De-obfuscate the truncated IV
	trunc_iv ^= IV_FUZZ;
	trunc_iv += getLE(*overhead32);
	trunc_iv &= IV_MASK;

	// Reconstruct the full IV counter
	u64 iv = ReconstructCounter<IV_BITS>(_window.LastAccepted(), trunc_iv);

	// Validate IV
	if (!_window.Validate(iv))
		return ERR_IV_DROP;

	// Decrypt and check MAC
	if (!_cipher.Decrypt(iv, ciphertext, plaintext_bytes))
		return ERR_MAC_DROP;

	// Accept this IV
	_window.Accept(iv);

	return plaintext_bytes;
}
