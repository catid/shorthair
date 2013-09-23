#include "wirehair/Wirehair.hpp"
#include "calico/Calico.hpp"
#include "Clock.hpp"
#include "Delegates.hpp"
#include "Enforcer.hpp"
#include "EndianNeutral.hpp"
#include "ReuseAllocator.hpp"
#include "BitMath.hpp"
#include "SmartArray.hpp"
#include "Thread.hpp"
#include "WaitableFlag.hpp"
#include "Mutex.hpp"
using namespace cat;

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cmath>
using namespace std;


/*
 * A visual representation of streaming in general (disregarding FEC):
 *
 * | <---------------------------- buffer size ----> | <- processed ---->
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 * ^                   ^
 * t=0                 t=max one-way latency expected
 *
 * The perceived latency at the receiver is the buffer size, and each of the
 * numbered bins may contain several packets transmitted together.
 *
 * Some example numbers:
 *
 * Stream data packet(s) every 10 ms
 * t = ~100 ms
 * buffer size = 250 ms
 *
 *
 * ==> Why use FEC?
 *
 * With RTT acknowledgement protocol like TCP this latency cannot be reached.
 * Furthermore head-of-line blocking in TCP can cause huge lag spikes in data.
 *
 * Using a custom "reliable" UDP implementation can avoid some of these problems
 * at the cost of high code complexity.  But latency is still bounded by RTT:
 * At best you could get 300 ms, but packetloss is *twice* as likely to kill
 * the NACK or the data now!
 *
 * But with FEC we can avoid TCP overhead and simply drop data when the link
 * fails beyond an expected rate rather than block subsequent data.
 *
 * Assume there is extra room in the channel for error correction symbols:
 * We could just send as many symbols as the link will allow, which would give
 * the best error correction performance.  In practice we would want to send
 * an amount that is reasonable.
 *
 * Using Reed-Solomon codes can achieve high-performance at FIXED code rates.
 * Furthermore they need to be designed with a FIXED number of packets ahead of
 * time, which means that in practice people have been writing *many* RS codes
 * and selecting between them for a single application.  And it all needs to be
 * rewritten when requirements change.
 *
 * Wirehair/RaptorQ improves on this, allowing us to use only as much bandwidth
 * as needed, covering any number of packets required.  These are "rateless"
 * codes that require an acceptable amount of performance loss compared to
 * RS-codes, and offering optimal use of the channel and lower latency compared
 * to ARQ-based approaches.
 *
 *
 * ==> Using UDP means we have to implement flow control right??
 *
 * Thankfully the data is constant-rate so there is no need for a
 * heavy-weight flow control algorithm.  We can just send data on a timer.
 * It doesn't need to be the same number of packets each time.
 *
 *
 * ==> What are the design decisions for error correction codes?
 *
 * (1) Code Groups : Which packets are covered by which code?
 * (2) Coding Rate : How many symbols to add for each code group?
 *
 *
 * ==> (2) How many additional symbols should we send?
 *
 * If a packet gets lost, sending one additional symbol can fill in for it with
 * high likelihood.  But it also has a small chance of being lost of course,
 * and packetloss tends to be bursty, so it is better to spread error correction
 * symbols over a longer amount of time.
 *
 * If channel packet drop decision can be modeled as an IID uniform random
 * variable, then the loss rate after FEC is applied can be evaluated using
 * equation (3) from:
 * http://www.eurecom.fr/en/publication/489/download/cm-nikane-000618.pdf
 *
 * It seems like the best redundancy should be selected by evaluating equation
 * (3) with several exponents until the estimated loss rate matches the
 * targetted loss rate.  Faster approaches are feasible.
 *
 *
 * ==> (1) How should we interleave/overlap/etc the codes?
 *
 * Wirehair's encoder uses a roughly linear amount of memory and time based on
 * the size of the input, so running multiple encoders is efficient.
 *
 * Since the data is potentially being read from a receiver in real-time, the
 * original data is sent first, followed by the error correction symbols.
 * This means that the original data has a tail of extra symbols that follow it.
 * These extra error correction symbols are sent along with new data for the
 * next code group, overlapping:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *                  ..   aa   aa   aa   aa   AA   AA   ..
 *        ..   bb   bb   bb   bb   BB   BB   ..
 *   cc   cc   cc   cc   CC   CC   ..
 *
 * Lower-case letters indicate check symbols, and upper-case letters indicate
 * original packets.
 *
 * The encoder keeps (buffer size in bins) / (code group size in bins) = P
 * encoders running in parallel.  Higher P is less efficient, because check
 * symbols sent are about (P-1)x less likely to be part of the code group.
 *
 * So we choose P = 2 and overlap just two encoders!
 *
 *
 * The next question is how large the code groups should be.  If they are bigger
 * than the after-transit buffer then problems occur as shown below:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *             !!   !!   aa   aa   AA   AA   AA   AA   ..
 *   bb   bb   BB   BB   BB   BB   !!   !!
 *
 * As you can see there are periods (marked with !!) where no check symbols can
 * be sent, or they would be too late.  This is both wasted bandwidth and
 * reducing the windows in which check symbols can be delivered to help.  This
 * is a very bad case to be in.
 *
 *
 * Another non-ideal case is where the code groups are too short:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *   DD   DD   cc   cc   CC   CC   aa   aa   AA   AA   gg   gg
 *   ee   ee   EE   EE   bb   bb   BB   BB   ff   ff   FF   FF
 *
 * Now it's clear that bandwidth is not being wasted.  However, if a burst loss
 * occurs, it is more likely to wipe out more symbols than can be recovered by
 * the chosen code rate.  For particularly long bursts, the only protection is
 * to make the code groups longer.
 *
 * So it's best to err on the side of code groups that are too short rather
 * than too long, between these two options.
 *
 *
 * When it is perfectly matched:
 *
 * | <---------------------------- buffer size ----> |
 * | <- in  transit -> |                             |
 * | 11 | 10 | 09 | 08 | 07 | 06 | 05 | 04 | 03 | 02 | 01 | 00 |
 *   cc   CC   CC   CC   aa   aa   aa   AA   AA   AA   ..
 *   ..   bb   bb   bb   BB   BB   BB   dd   dd   dd   DD   DD
 *
 * Knowing the transit time for data is essential in estimating how large the
 * code group size should be.  This allows the encoder to avoid sending data
 * that will be useless at the decoder.  This also allows the encoder to make
 * the most of the buffer to prevent bursty losses from affecting the recovery,
 * assuming that the buffer size has been selected to be much larger than burst
 * loss periods.
 *
 * And again, we want to err on the side of short code groups.
 *
 * let RTT_high be a high estimate of the round-trip time.
 * estimate the one-way transit time by RTT_high/2, and so:
 *
 * (code group length) = ((buffer size) - (RTT_high/2)) / 2.1
 *
 * The 2.1 factor and RTT calculation can be modified for realistic scenarios.
 *
 * This gives us the number of packets to include in each group, and the data
 * encoder just alternates between two Wirehair instances, feeding one and
 * generating check symbols from the other.
 * 
 *
 * ==> Aside from FEC what else do we need?
 *
 * FEC assumes we have a way to tell if a packet arrived corrupted or not.
 * So we need to add a good checksum.
 *
 * Furthermore, each packet needs to be tagged with a unique ID number so that
 * we can tell which code group it is from, for a start.  And we need a way to
 * check if a packet is corrupted that is stronger than the normal (sometimes
 * optional) 16-bit UDP CRC.
 *
 * Happily, it turns out that an authenticated encryption scheme with a stream-
 * cipher and MAC provides security, integrity, and a useful ID number.
 * This means that almost for free we also get secure data transmission.
 *
 * SSL runs over TCP which makes it impractical for data transmission in our
 * case, but it may be useful for a key exchange handshake.
 *
 *
 * ==> Putting it all together
 *
 * Round-trip time must be measured to calculate the rate at which the sender
 * swaps encoders.  Packetloss must be measured to calculate the number of
 * extra check symbols to send.
 *
 * So, periodically the sender should send a flag in a data packet that
 * indicates a "ping."  The receiver should respond as fast as possible to the
 * ping with a "pong" that includes packet loss information.  It helps to set
 * the "ping" flag at the front of a set of data to avoid queuing delays
 * affecting the measured transit time.
 * 
 * The data is encrypted, so each packet has a unique identifier.  The receiver
 * notes gaps in the packet id sequence that last longer than the buffer size
 * as losses.  The collected loss statistics will be sent in "pong" messages.
 *
 * The sender is only sending recovery symbols for one code group at a time, so
 * only one encoder is needed.
 *
 * The receiver can opportunistically apply the decoder when packets get lost.
 * And it only applies the decoder to the most recent code group, so only one
 * decoder instance is needed.
 */



/*
 * Brook Protocol
 *
 * This protocol implements a single FEC/UDP stream.  Another control channel
 * must be used for secret key agreement and connection/disconnection events.
 *
 *
 * Usage:
 *
 * The data source implements IDataSource and fills in the SourceSettings
 * structure with parameters to control the data flow.  Call ::Tick() periodically
 * at the rate you want to transmit data.  10 ms or faster is a good idea.
 * And call ::Recv() when a UDP packet arrives.  The data source object will
 * call your IDataSource methods when it needs to read data from the input or
 * needs to send a UDP packet to the remote sink.
 *
 * The data sink implements IDataSink and fills in the SinkSettings
 * structure with parameters to control the data flow.  Call ::Recv() when UDP
 * packets arrive.  The data sink object will call your IDataSink methods when
 * it needs to send a UDP packet to the remote source or when it has received
 * the next packet in the data stream.
 *
 *
 * Source -> Sink data packet format:
 *
 * <group[1 byte]> (brook-wirehair)
 * <block count[2 bytes]> (brook-wirehair)
 * <block id[2 bytes]> (brook-wirehair)
 * {...block data...}
 * <MAC[8 bytes]> (calico)
 * <IV[3 bytes]> (calico)
 *
 * MAC+IV are used for Calico encryption (11 bytes overhead).
 * Group: Which code group the data is associated with.
 * N = Block count: Total number of original data packets in this code group.
 * I = Block id: Identifier for this packet.
 *
 * In this scheme,
 * 		I < N are original, and
 * 		I >= N are Wirehair recovery packets.
 *
 * The Block ID uses a wrapping counter that reduces an incrementing 32-bit
 * counter to a 16-bit counter assuming that packet re-ordering does not exceed
 * 32768 consecutive packets.  (IV works similarly to recover a 64-bit ID)
 *
 * Total overhead = 16 bytes per packet.
 *
 *
 * Sink -> Source pong packet format:
 *
 * <group[1 byte]>
 * <seen count[4 bytes]>
 * <total count[4 bytes]>
 *
 * This message is sent in reaction to a new code group on the receipt of the
 * first original data packet to update the source's redundancy in reaction to
 * measured packet loss as seen at the sink and to measure the round-trip time
 * for deciding how often to switch codes.
 */


static const int SKEY_BYTES = 32;
static const int PROTOCOL_OVERHEAD = 1 + 2 + 2;
static const int ORIGINAL_OVERHEAD = PROTOCOL_OVERHEAD + calico::Calico::OVERHEAD;
static const int RECOVERY_OVERHEAD = PROTOCOL_OVERHEAD + 2 + calico::Calico::OVERHEAD;
static const int BROOK_OVERHEAD = RECOVERY_OVERHEAD; // 18 bytes + longest packet size for recovery packets
static const int PONG_SIZE = 1 + 4 + 4;
static const int MAX_CHUNK_SIZE = 65535; // Largest allowed packet chunk size
static const u8 PAST_GROUP_THRESH = 127; // Group ID wrap threshold


/*
 * Normal Approximation to Bernoulli RV
 *
 * P(X > r), X ~ B(n+r, p)
 *
 * Recall: E[X] = (n+r)*p, SD(X) = sqrt((n+r)*p*(1-p))
 *
 * X is approximated by Y ~ N(mu, sigma)
 * where mu = E[X], sigma = SD(X).
 *
 * And: P(X > r) ~= P(Y >= r + 0.5)
 *
 * For this to be somewhat accurate, np >= 10 and n(1-p) >= 10.
 */

#define INVSQRT2 0.70710678118655

// Precondition: r > 0
// Returns probability of loss for given configuration
double NormalApproximation(int n, int r, double p) {
	const int m = n + r;

	double u = m * p;
	double s = sqrt(u * (1. - p));

	return 0.5 * erfc(INVSQRT2 * (r - u - 0.5) / s);
}

int CalculateRedundancy(double p, int n, double Qtarget) {
	// TODO: Skip values of r to speed this up
	int r = 0;
	double q;

	do {
		++r;
		q = NormalApproximation(n, r, p);
	} while (q > Qtarget);

	++r;

	// Add one extra symbol to fix error of approximation
	if (n * p < 10. || n * (1 - p) < 10.) {
		++r;
	}

	return r;
}


class LossEstimator {
	static const int BINS = 32;
	struct {
		u32 seen, count;
	} _bins[BINS];
	int _count, _index;

	// Minimum allowed loss estimate
	float _min_loss;

	// Final massaged value:
	float _loss;

public:
	void Initialize(float min_loss) {
		_index = 0;
		_count = 0;
		_min_loss = min_loss;
		_loss = min_loss;
	}

	void Insert(u32 seen, u32 count) {
		// Insert data
		_bins[_index].seen = seen;
		_bins[_index].count = count;

		// Wrap around
		if (++_index >= BINS) {
			_index = 0;
		}

		// If not full yet,
		if (_count < BINS) {
			_count++;
		}
	}

	// Pick estimated loss based on history
	void Calculate() {
		const int len = _count;
		u64 seen = 0, count = 0;

		for (int ii = 0; ii < len; ++ii) {
			seen += _bins[ii].seen;
			count += _bins[ii].count;
		}

		_loss = (float)((count - seen) / (double)count);

		// Clamp value
		if (_loss < _min_loss) {
			_loss = _min_loss;
		}

		// TODO: Validate that this is a good predictor
	}

	float Get() {
		return _loss;
	}
};


class DelayEstimator {
	static const int BINS = 32;
	struct {
		int delay;
	} _bins[BINS];
	int _count, _index;

	// Clamp values
	int _min_delay, _max_delay;

	// Final massaged value:
	int _delay;

public:
	void Initialize(int min_delay, int max_delay) {
		_index = 0;
		_count = 0;
		_min_delay = min_delay;
		_max_delay = max_delay;
		_delay = min_delay;
	}

	void Insert(int delay) {
		// Insert data
		_bins[_index].delay = delay;

		// Wrap around
		if (++_index >= BINS) {
			_index = 0;
		}

		// If not full yet,
		if (_count < BINS) {
			_count++;
		}
	}

	// Pick estimated upper-bound on one-way s2c delay based on history
	void Calculate() {
		u64 sum = 0;
		const int len = _count;

		for (int ii = 0; ii < len; ++ii) {
			int delay = _bins[ii].delay;

			sum += delay;
		}

		_delay = (int)(sum / len);

		if (_delay < _min_delay) {
			_delay = _min_delay;
		} else if (_delay > _max_delay) {
			_delay = _max_delay;
		}

		// TODO: Validate that this is a good predictor
	}

	int Get() {
		return _delay;
	}
};



class IDataSource {
public:
	// Data to send to remote host
	virtual void SendData(void *buffer, int bytes) = 0;
};



struct SourceSettings {
	float min_loss;				// [0..1] packetloss probability lower limit
	int min_delay, max_delay;	// Milliseconds clamp values for delay estimation
	int buffer_time;			// Milliseconds for end-to-end buffering
	int max_data_size;			// Maximum input read size in bytes
	IDataSource *source;		// Data source
};


struct Sent : BatchHead {
	u16 size;

	// Data follows (length+ bytes)
	u8 data[1];
};


/*
 * Run the encoder in a separate thread to avoid adding latency spikes
 * to the original data packet stream.
 *
 * Not thread-safe.  It assumes that only one thread is accessing its
 * interface at a time.
 */
class EncoderThread : public Thread {
protected: // Shared data:
	bool _initialized;
	volatile bool _kill;
	WaitableFlag _wake;

	// Packet buffers are allocated with room for the protocol overhead + data
	ReuseAllocator _allocator;

	// Workspace to accumulate sent packets
	Sent *_sent_head, *_sent_tail;
	int _block_count;	// Number of blocks 
	int _largest;		// Number of bytes max, excluding 2 byte implied length field

	// Next block id to produce
	u32 _next_block_id;

	// Encoder is ready to produce symbols?
	// Cleared by main thread, set by encoder thread
	volatile bool _encoder_ready;

	// Lock to hold during processing to avoid reentrancy
	Mutex _processing_lock;

	// Indicates previous group can be disposed
	volatile bool _last_garbage;

private: // Thread-Private data:
	wirehair::Encoder _encoder;

	// Code group size
	int _group_largest, _group_count;

	// Fixed code group list
	Sent *_group_head, *_group_tail;

	// Size of block for this group
	int _group_block_size;

	// Large message buffer for code group
	SmartArray<u8> _encode_buffer;

	CAT_INLINE void FreeGarbage() {
		if (_last_garbage) {
			_last_garbage = false;
			// Free packet buffers
			_allocator.ReleaseBatch(BatchSet(_group_head, _group_tail));
		}
	}

	virtual bool Entrypoint(void *param) {
		while (!_kill) {
			_wake.Wait();
			if (!_kill) {
				Process();
			}
		}
	}

	void Process() {
		AutoLock lock(_processing_lock);

		// Byte per data chunk
		int chunk_size = _group_largest;
		int block_count = _group_count;

		CAT_ENFORCE(block_count > 1 && chunk_size > 0);

		// NOTE: Blocks are chunks with 2-byte lengths prepended
		int block_size = 2 + chunk_size;
		_group_block_size = block_size;

		// Calculate size of encoded messages
		u32 message_size = block_count * block_size;

		// Grow buffer
		_encode_buffer.resize(message_size);

		// For each sent packet,
		u8 *buffer = _encode_buffer.get();
		for (Sent *p = _group_head; p; p = (Sent*)p->batch_next) {
			u16 size = p->size;

			// Start each block off with the 16-bit size
			*(u16*)buffer = getLE(size);
			buffer += 2;

			// Add packet data in
			memcpy(buffer, p->data + PROTOCOL_OVERHEAD, size);

			// Zero the high bytes
			memset(buffer + size, chunk_size - size);

			// On to the next
			buffer += chunk_size;
		}

		// NOTE: After this function call, the input data can be safely modified so long
		// as Encode() requests come after the original data block count.
		CAT_ENFORCE(!_encoder.BeginEncode(_encode_buffer.get(), message_size, block_size));

		_next_block_id = block_count;

		// Avoid re-ordering writes by optimizer at compile time
		CAT_FENCE_COMPILER;

		_encoder_ready = true;
	}

public:
	CAT_INLINE EncoderThread() {
		_initialized = false;
	}
	CAT_INLINE virtual ~EncoderThread() {
		Finalize();
	}

	void Initialize(int max_data_size) {
		Finalize();

		_allocator.Initialize(BOOK_OVERHEAD + max_data_size);

		_kill = false;
		_last_garbage = false;
		_encoder_ready = false;
		_next_block_id = 0;
		_largest = 0;
		_block_count = 0;
		_sent_head = _sent_tail = 0;

		StartThread();

		_initialized = true;
	}

	void Finalize() {
		if (_initialized) {
			_kill = true;

			_wake.Set();

			WaitForThread();

			FreeGarbage();

			_initialized = false;
		}
	}

	Sent *QueueSent() {
		// Allocate sent packet buffer
		Sent *p = _allocator.AcquireObject<Sent>();

		// If this new packet is larger than the previous ones,
		if (_largest < p->size) {
			// Remember the largest size for when we start emitting check symbols
			_largest = p->size;
		}

		// Insert at end of list
		if (_sent_tail) {
			_sent_tail->batch_next = p;
		} else {
			_sent_head = p;
		}
		_sent_tail = p;
		p->batch_next = 0;

		++_block_count;

		CAT_ENFORCE(_block_count <= wirehair::CAT_WIREHAIR_MAX_N);
	}

	CAT_INLINE GetCurrentCount() {
		return _block_count;
	}

	void EncodeQueued() {
		// If no data to encode,
		if (_block_count <= 0) {
			return;
		}

		if (!_initialized) {
			Initialize();
		}

		// Hold processing lock to avoid calling this too fast
		AutoLock lock(_processing_lock);

		// NOTE: After N = 1 case, next time encoding starts it will free the last one
		FreeGarbage();

		// Flag encoder as being busy processing previous data
		_encoder_ready = false;

		// Move code group profile into private memory
		_group_largest = _largest;
		_group_count = _block_count;
		_group_head = _sent_head;
		_group_tail = _sent_tail;

		// Flag garbage for takeout
		_last_garbage = true;

		// Clear the shared workspace for new data
		_largest = 0;
		_block_count = 0;
		_sent_head = _sent_tail = 0;

		// If N = 1,
		if (_block_count == 1) {
			// Set up for special mode
			_encoder_ready = true;
			_group_block_size = _group_head->size;
		} else {
			// Wake up the processing thread
			_wake.Set();
		}
	}

	// Returns false if recovery blocks cannot be sent yet
	int GenerateRecoveryBlock(u8 *buffer) {
		if (!_encoder_ready) {
			return 0;
		}

		// Get next block ID to send
		u32 block_id = _next_block_id++;

		// Add low bits of check symbol number
		*(u16*)buffer = getLE((u16)block_id);

		// Add block count
		*(u16*)(buffer + 2) = getLE((u16)_group_count);

		if (_group_count == 1) {
			// Copy original data directly
			memcpy(buffer + 4, _group_head->data + PROTOCOL_OVERHEAD, _group_block_size);
		} else {
			CAT_ENFORCE(_group_block_size == _encoder.Encode(block_id, buffer + 4));

			FreeGarbage();
		}

		return 4 + _group_block_size;
	}
};


class BrookSource {
	bool _intialized;

	Clock _clock;

	SourceSettings _settings;

	calico::Calico _cipher;

	EncoderThread _encoder;

	DelayEstimator _delay;
	LossEstimator _loss;

	// Calculated symbol rate from loss
	u32 _check_symbols_max;
	float _check_symbols_per_ms;

	// Last time we had a tick
	u32 _last_tick;
	u8 _code_group;

	// Swap times for each code group for RTT calculation
	u32 _group_stamps[256];

	// Packet workspace buffer
	SmartArray<u8> _packet_buffer;

	// Calculated interval from delay
	u32 _swap_interval;

	// Next time to trigger a swap
	u32 _swap_trigger;

	// Next symbol ID or 0 for uninitialized state
	u32 _next_id;

	// Send a check symbol
	void SendCheckSymbol() {
		u8 *buffer = _packet_buffer.get();

		int bytes = _encoder.GenerateRecoveryBlock(buffer + 1);

		// If no data to send,
		if (bytes <= 0) {
			// Abort
			return;
		}

		// Prepend the code group
		buffer[0] = _code_group;

		// Encrypt
		bytes = _cipher.Encrypt(buffer, 1 + bytes, buffer, _packet_buffer.size());

		// Transmit
		_settings.source->SendData(buffer, bytes);
	}

	// Calculate interval from delay
	void CalculateInterval() {
		int delay = _delay.Get();

		// TODO: Calculate _swap_interval
	}

	// Calculate symbol rate from loss
	void CalculateRate() {
		float loss = _loss.Get();

		// TODO: Calculate _check_symbols_max and _check_symbols_per_ms
	}

	// From pong message, round-trip time
	CAT_INLINE void UpdateRTT(int ms) {
		CAT_ENFORCE(ms >= 0);

		// Approximate delay with RTT / 2.
		// TODO: Adjust to match the asymmetry of your channel,
		// or use exact time measurements when available instead.
		int delay = ms / 2;

		_delay.Insert(delay);
		_delay.Calculate();

		CalculateInterval();
	}

	// From pong message, number of packets seen out of count in interval
	CAT_INLINE void UpdateLoss(u32 seen, u32 count) {
		CAT_ENFORCE(seen <= count);

		if (count > 0) {
			_loss.Insert(seen, count);
			_loss.Calculate();

			CalculateRate();
		}
	}

public:
	CAT_INLINE BrookSource() {
		_intialized = false;
	}

	CAT_INLINE virtual ~BrookSource() {
		Finalize();
	}

	// On startup:
	bool Initialize(const u8 key[SKEY_BYTES], const SourceSettings &settings) {
		Finalize();

		_clock.OnInitialize();

		if (_cipher.Initialize(key, "BROOK", calico::RESPONDER)) {
			return false;
		}

		_settings = settings;

		CAT_ENFORCE(_settings.max_size <= MAX_CHUNK_SIZE);

		_encoder.Initialize(_settings.max_size);

		_delay.Initialize(_settings.min_delay, _settings.max_delay);
		_loss.Initialize(_settings.min_loss);

		_last_tick = 0;
		_code_group = 0;
		_input_symbol = 0;

		// Allocate recovery packet workspace
		_packet_buffer.resize(BROOK_OVERHEAD + _settings.max_size);

		CAT_OBJCLR(_group_stamps);

		CalculateInterval();
		CalculateRate();

		_intialized = true;
	}

	void Finalize() {
		if (_intialized) {
			_encoder.Finalize();

			_clock.OnFinalize();

			_intialized = false;
		}
	}

	// Send some data with low latency
	void Send(const void *data, int len) {
		CAT_ENFORCE(len < _settings.max_size);

		Sent *p = _encoder.QueueSent();

		// Store length
		p->size = (u16)len;

		u8 *buffer = p->data;

		// Add next code group (this is part of the code group after the next swap)
		buffer[0] = _code_group + 1;

		u16 block_count = _encoder.GetCurrentCount();

		// On first packet of a group,
		if (block_count == 1) {
			// Tag this new group with the start time
			_group_stamps[_code_group + 1] = m_clock.msec();
		}

		// Add check symbol number
		*(u16*)(buffer + 1) = getLE(block_count - 1);

		// For original data send the current block count, which will
		// always be one ahead of the block ID.
		// NOTE: This allows the decoder to know when it has received
		// all the packets in a code group for the zero-loss case.
		*(u16*)(buffer + 1 + 2) = getLE(block_count);

		// Copy input data into place
		memcpy(buffer + PROTOCOL_OVERHEAD, data, len);

		// Encrypt
		bytes = _cipher.Encrypt(buffer, PROTOCOL_OVERHEAD + bytes, _packet_buffer.get(), _packet_buffer.size());

		// Transmit
		_settings.source->SendData(_packet_buffer.get(), bytes);
	}

	// Called once per tick, send all pending data and check symbols, providing
	// a timestamp in milliseconds
	void Tick(u32 ms) {
		// If it is time to swap the buffer,
		if ((s32)(ms - _swap_trigger) > 0) {
			_swap_trigger = ms + _swap_interval;

			CalculateRedundancy();

			// Start encoding queued data in another thread
			_encoder.EncodeQueued();
		}

		// Calculate tick interval
		u32 tick_interval = ms - _last_tick;
		_last_tick = ms;

		// Calculate symbols to send
		u32 check_symbols = _check_symbols_per_ms * tick_interval;
		if (check_symbols > _check_symbols_max) {
			check_symbols = _check_symbols_max;
		}

		for (;;) {
			// Compose outgoing packet
			u8 *buffer = _packet_buffer.get();

			// Add next code group (this is part of the code group after the next swap)
			buffer[0] = _code_group + 1;

			// If just swapped,
			if (_next_count == 0) {
				// Tag this new group with the start time
				_group_stamps[_code_group + 1] = ms;
			} else if (_next_count >= wirehair::CAT_WIREHAIR_MAX_N) {
				// Force swap early
				swap = true;
			}

			// Add check symbol number
			*(u16*)(buffer + 1) = getLE((u16)(_next_count - 1));

			// For original data send the current block count, which will
			// always be one ahead of the block ID.
			// NOTE: This allows the decoder to know when it has received
			// all the packets in a code group for the zero-loss case.
			*(u16*)(buffer + 1 + 2) = (u16)_next_count;

			// Copy data part
			memcpy(buffer + PROTOCOL_OVERHEAD, p->data, bytes);

			// Encrypt
			bytes = _cipher.Encrypt(buffer, PROTOCOL_OVERHEAD + bytes, buffer, _packet_buffer.size());

			// Transmit
			_settings.source->SendData(buffer, bytes);

			// If swapping now,
			if (swap) {
				swap = false;

				SetupEncoder();
			}

			// Send next check symbol
			if (check_symbols > 0) {
				SendCheckSymbol();
				--check_symbols;
			}
		}

		// TODO

		// Read data in chunks
		int bytes;
		while ((bytes = _settings.source->ReadData(data, _settings.chunk_size))) {
			// NOTE: For now, require that the data returned is exactly the size requested.
			// This has some obvious failure modes (very small data), but avoids a lot of
			// complications.
			CAT_ENFORCE(bytes == _settings.chunk_size);

			// Append to buffer
			_buffer.insert(_buffer.end(), data, data + bytes);

			// Add next code group (this is part of the code group after the next swap)
			buffer[0] = _code_group + 1;

			// If just swapped,
			if (_input_symbol == 0) {
				// Tag this new group with the start time
				_group_stamps[_code_group + 1] = ms;
			}

			// Add check symbol number
			*(u16*)(buffer + 1) = getLE((u16)_input_symbol);

			// Set block count to zero for input symbols
			// TODO: May need to set block count for at least the last symbol
			*(u16*)(buffer + 1 + 2) = 0;

			// Encrypt
			bytes = _cipher.Encrypt(buffer, bytes + PROTOCOL_OVERHEAD, buffer, sizeof(buffer));

			// Transmit
			_settings.source->SendData(buffer, bytes);

			// Next input symbol id
			++_input_symbol;

			// Send next check symbol
			if (check_symbols > 0) {
				SendCheckSymbol();
				--check_symbols;
			}
		}

		// Send remaining check symbols
		while (check_symbols > 0) {
			SendCheckSymbol();
			--check_symbols;
		}
	}

	// On packet received
	void Recv(u32 ms, u8 *pkt, int len) {
		u64 iv;
		len = _cipher.Decrypt(pkt, len, iv);

		// If it is a pong,
		if (len == PONG_SIZE) {
			// Read packet data
			u8 code_group = pkt[0];
			u32 seen = getLE(*(u32*)(pkt + 1));
			u32 count = getLE(*(u32*)(pkt + 1 + 4));

			// Calculate RTT
			int rtt = ms - _group_stamps[code_group];

			// Compute updates
			UpdateRTT(rtt);
			UpdateLoss(seen, count);
		}
	}
};






class IDataSink {
public:
	// Called with the latest data block from remote host
	virtual void OnPacket(void *packet) = 0;

	// Data to send to remote host
	virtual void SendData(void *buffer, int bytes) = 0;
};


struct SinkSettings {
	int chunk_size;		// Size of data chunks in bytes
	int group_time;		// Milliseconds that each code group will last
	IDataSink *sink;	// Interface
};


struct Packet : BatchHead {
	// Block ID for this packet
	u32 id;

	// Data follows
	u8 data[1];
};


struct CodeGroup {
	// Is code group open?
	bool open;

	// Is code group completely passed?
	bool done;

	// Timestamp on first packet for this group
	u32 open_time;

	// Largest ID seen for each code group, for decoding the ID
	u32 largest_id;

	// Last seen block count for each code group
	u16 block_count;

	// Received symbol counts
	u16 original_seen;
	u16 total_seen;

	// Data that has been passed along already
	Packet *passed_head, *passed_tail;

	// Sorted out-of-sequence data: head=lowest id, tail=highest id
	Packet *oos_head, *oos_tail;

	// Recovery symbols
	Packet *recovery_head, *recovery_tail;

	void Open(u32 ms) {
		open = true;
		open_time = ms;

		done = false;
		largest_id = 0;
		block_count = 0;
		original_seen = 0;
		total_seen = 0;
		passed_head = 0;
		passed_tail = 0;
		oos_head = 0;
		oos_tail = 0;
		recovery_head = 0;
		recovery_tail = 0;
	}

	bool CanRecover() {
		// If block count is still unknown,
		if (block_count <= 0) {
			return false;
		}

		// If recovery is possible,
		return total_seen >= block_count;
	}

	void Close(ReuseAllocator &allocator) {
		open = false;
		done = true;

		// Free allocated packet memory O(1)
		allocator.ReleaseBatch(BatchSet(passed_head, passed_tail));
		allocator.ReleaseBatch(BatchSet(oos_head, oos_tail));
		allocator.ReleaseBatch(BatchSet(recovery_head, recovery_tail));
	}

	void AddPassed(Packet *p) {
		++original_seen;
		++total_seen;

		// Insert at head
		if (passed_head) {
			p->batch_next = passed_head;
		} else {
			passed_head = passed_tail = p;
		}
		passed_head = p;
	}

	void AddRecovery(Packet *p) {
		++total_seen;

		// Insert at head
		if (recovery_head) {
			p->batch_next = recovery_head;
		} else {
			recovery_head = recovery_tail = p;
		}
		recovery_head = p;
	}

	// Remove head of OOS list
	// Precondition: There is at least one element in the list
	void PopOOS() {
		--original_seen;
		--total_seen;

		Packet *p = oos_head;

		CAT_ENFORCE(p && original_seen > 0);

		// Shift ahead
		p = (Packet*)p->batch_next;
		oos_head = p;

		// If list is now empty,
		if (!p) {
			oos_tail = 0;
		}
	}

	void AddOOS(Packet *p) {
		++original_seen;
		++total_seen;

		// Insert into empty list
		if (!oos_head) {
			oos_head = oos_tail = p;
			p->batch_next = 0;
			return;
		}

		const u32 id = p->id;

		// Attempt fast O(1) insertion at end
		if (oos_tail && id > oos_tail->id) {
			// Insert at the end
			oos_tail->batch_next = p;
			p->batch_next = 0;
			oos_tail = p;
			return;
		}

		// Search for insertion point from front, shooting for O(1)
		Packet *prev = 0, *next;
		for (next = oos_head; next; next = (Packet*)next->batch_next) {
			if (id < next->id) {
				break;
			}
		}

		// If inserting after prev,
		if (prev) {
			prev->batch_next = p;
		} else {
			oos_head = p;
		}
		if (!next) {
			oos_tail = p;
		}
		p->batch_next = next;
	}
};


// TODO: Add startup mode where we accept any code group as the first one

class BrookSink {
	SinkSettings _settings;

	calico::Calico _cipher;

	// Is decoder active?
	bool _decoding;

	// NOTE: Using codec directly since we want to regenerate blocks instead of whole messages
	wirehair::Codec _decoder;

	// Next expected (code group, block id)
	// Will be passed directly to IDataSink when received
	u8 _next_group;
	u32 _next_id;

	// Timestamp after which the group has expired and we give up and move on
	u32 _group_timeout;

	// Statistics since the last pong
	u32 _seen, _count;

	// Packet buffer allocator
	ReuseAllocator _allocator;

	// Code groups
	CodeGroup _groups[256];

	// Send collected statistics
	void SendPong(int code_group) {
		u8 pkt[PONG_SIZE + calico::Calico::OVERHEAD];

		// Write packet
		pkt[0] = (u8)code_group;
		*(u32*)(pkt + 1) = getLE(_seen);
		*(u32*)(pkt + 1 + 4) = getLE(_count);

		// Reset statistics
		_seen = _count = 0;

		// Encrypt pong
		int len = _cipher.Encrypt(pkt, PONG_SIZE, pkt, sizeof(pkt));

		CAT_DEBUG_ENFORCE(len == sizeof(pkt));

		// Send it
		_settings.sink->SendData(pkt, len);
	}

	Packet *AllocatePacket(u32 id, const void *data) {
		Packet *p = _allocator.AcquireObject<Packet>();
		p->batch_next = 0;
		p->id = id;
		memcpy(p->data, data, _settings.chunk_size);
		return p;
	}

	void FreePacket(Packet *p) {
		_allocator.ReleaseBatch(p);
	}

	void FinishGroup(Group *group) {
		CAT_DEBUG_ENFORCE(group == &_groups[_next_group]);

		for (;;) {
			// If group was open,
			if (group->open) {
				// Close off this group.
				group->Close(_allocator);
			}

			// Decoder is now inactive
			_decoding = false;

			// Set next expected (group, id)
			_next_group++;
			_next_id = 0;

			// The relative group will now be -1 = 255,
			// so further packets for this group will be
			// dropped until the group id rolls back around.

			// Pass as many from the next group as we can now
			group = &_group[_next_group];

			// If not finished another group immediately,
			if (!ProcessOOS(group)) {
				// If group is not recoverable now,
				if (!group->CanRecover() || !AttemptRecovery(group)) {
					break;
				}

				// Recover and pass all the packets
				RecoverGroup(group);
			}
		}
	}

	// Returns true if code group was finished, so packet can be discarded
	bool ProcessOOS(CodeGroup *group) {
		// O(1) Check OOS
		Packet *oos = group->oos_head;
		while (oos && oos->id == _next_id) {
			// Pass along queued data
			_settings.sink->OnPacket(oos->data);

			// Increment ID
			_next_id++;

			// If just finished the group,
			if (block_count && _next_id >= group->block_count) {
				return true;
			}

			// Store next in oos list
			Packet *next = (Packet*)oos->batch_next;

			// Pop off OOS head
			group->PopOOS();

			// Add it to passed list
			group->AddPassed(oos);

			// Continue with next
			oos = next;
		}

		return false;
	}

	// Recover the remaining blocks for a code group and pass them on
	void RecoverGroup(CodeGroup *group) {
		// Acquire some memory temporarily to store the recovered block
		Packet *p = _allocator.AcquireObject<Packet>();

		do {
			// Reconstruct the block for the next expected ID
			_decoder.ReconstructBlock(_next_id, p->data);

			// Pass along queued data
			_settings.sink->OnPacket(p->data);

			// Increment ID
			_next_id++;

			// Process OOS original data until we get stuck again or finish
		while (!ProcessOOS(group));

		// NOTE: Message is now completely delivered

		// Free temporary memory
		FreePacket(p);
	}

	// Returns true if recovery succeeded
	bool AttemptRecovery(CodeGroup *group, Packet *p = 0) {
		wirehair::Result r;

		// If not decoding yet,
		if (!_decoding) {
			r = _decoder.InitializeDecoder(block_count * _settings.chunk_size, _settings.chunk_size);

			// We should always initialize correctly
			CAT_ENFORCE(!r && _decoder.BlockCount() == block_count);

			// Decoding process has started
			_decoding = true;

			// Add passed packets
			for (Packet *op = group->passed_head; op; op = (Packet*)op->batch_next) {
				r = _decoder.DecodeFeed(op->id, op->data);
				if (!r) {
					return true;
				}
			}

			// Add OOS packets
			for (Packet *op = group->oos_head; op; op = (Packet*)op->batch_next) {
				r = _decoder.DecodeFeed(op->id, op->data);
				if (!r) {
					return true;
				}
			}

			// Add Recovery packets
			for (Packet *op = group->oos_head; op; op = (Packet*)op->batch_next) {
				r = _decoder.DecodeFeed(op->id, op->data);
				if (!r) {
					return true;
				}
			}
		} else if (p) {
			// Feed the latest packet
			r = _decoder.DecodeFeed(p->id, p->data);
			if (!r) {
				return true;
			}
		} else {
			// Cannot recover without any new data
			return false;
		}

		return false;
	}

public:
	// On startup:
	bool Initialize(const u8 key[SKEY_BYTES], const SinkSettings &settings) {
		if (_cipher.Initialize(key, "BROOK", calico::INITIATOR)) {
			return false;
		}

		_settings = settings;

		_decoding = false;

		// Expect (0, 0) first
		_next_group = _next_id = 0;

		_group_timeout = 0;

		// Initialize the packet allocator
		_allocator.Initialize(sizeof(Packet)-1 + _settings.chunk_size);

		// Clear group data
		CAT_OBJCLR(_groups);
	}

	// On tick 
	void Tick(u32 ms) {
		CodeGroup *group = &_groups[_next_group];

		// Periodically check for a code group timeout:

		// If active group has expired,
		if (ms > _group_timeout) {
			// Deliver any packets we did receive:

			// If group is open,
			if (group->open) {
				// For each packet in order,
				for (Packet *p = group->oos_head; p; p = (Packet*)p->batch_next) {
					// Pass packet along
					_settings.sink->OnPacket(p->data);
				}

				// Finish this group and move on to the next one
				FinishGroup(group);

				// Grab next group
				group = _groups[_next_group];

				_group_timeout = group->open_time + _settings.group_time * 2;
			}
		}
	}

	// On packet received
	void Recv(u32 ms, u8 *pkt, int len) {
		u64 iv;
		len = _cipher.Decrypt(pkt, len, iv);

		// TODO: Encode data with length prepended.

		// If packet contains data,
		if (len > PROTOCOL_OVERHEAD) {
			// Read packet data
			u8 code_group = pkt[0];

			// Rotate group id
			u8 relative_group = code_group - _next_group;

			// If received group is in the past,
			if (relative_group > PAST_GROUP_THRESH) {
				// Ignore data in the past, which happens often
				// when there is no packet loss and the error
				// correction codes are not useful.
				return;
			}

			CodeGroup *group = &_groups[code_group];

			u32 id = getLE(*(u16*)(pkt + 1));
			u16 block_count = getLE(*(u16*)(pkt + 1 + 2));
			u8 *data = pkt + PROTOCOL_OVERHEAD;

			// Reconstruct block id
			id = ReconstructCounter<16, u32>(group->largest_id, id);

			// Pong first packet of each group as fast as possible
			if (id == 0) {
				SendPong(code_group);
			}

			// Attempt to fill in block count if it is already known
			if (block_count == 0) {
				block_count = group->block_count;
			}

			// If group is not open yet,
			if (!group->open) {
				// Open group
				group->Open(ms);
			}

			// If ID is the largest seen so far,
			if (id > group->largest_id) {
				// Update largest seen ID for decoding ID in next packet
				group->largest_id = id;
			}

			// Packet that will contain this data
			Packet *p;

			// If it is next in sequence,
			if (code_group == _next_group && id == _next_id) {
				// Pass it along immediately
				_settings.sink->OnPacket(data);

				// Increment ID
				_next_id++;

				// If just finished the group,
				if ((block_count && _next_id >= block_count) ||
					ProcessOOS(group)) {
					// Zero-loss case.
					// ProcessOOS() can return true and finish the group when
					// all needed packet data was found in OOS list.
					FinishGroup(group);
					return;
				}

				// NOTE: At this point we have not received all the original
				// data yet, so store anything we get for recovery:
				p = AllocatePacket(id, data);

				// Add to passed list since it was already passed along
				group->AddPassed(p);

				// Fall-thru to handle out of sequence case with recovery:
			} else {
				// Zero-loss case: If seen all the original data for this group,
				if (block_count && group->original_seen >= block_count) {
					// Ignore any new data
					return;
				}

				// Otherwise: Store any data we receive until we get a chance
				// to run the decoder on it.
				p = AllocatePacket(id, data);

				// If out of sequence original data,
				if (!block_count || id < block_count) {
					// Add to out of sequence list
					group->AddOOS(p);
				} else {
					// Add to recovery list
					group->AddRecovery(p);
				}

				// Fall-thru to try to recover with the new data
			}

			// If waiting for this group and recovery is possible,
			if (code_group == _next_group && group->CanRecover()) {
				if (AttemptRecovery(group, p)) {
					// Recover and pass all the packets
					RecoverGroup(group);

					// Finish off this group
					FinishGroup(group);

					// Stop here
					return;
				}
			}

			// TODO: Implement IV-based packet-loss estimator
		}
	}
};









int main()
{
	return 0;
}


// TODO: Test it!

