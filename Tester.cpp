#include "wirehair/Wirehair.hpp"
#include "calico/Calico.hpp"
#include "Clock.hpp"
#include "Delegates.hpp"
#include "Enforcer.hpp"
#include "EndianNeutral.hpp"
#include "ReuseAllocator.hpp"
#include "BitMath.hpp"
using namespace cat;

#include <vector>
#include <iostream>
#include <iomanip>
#include <fstream>
#include <cmath>
using namespace std;

static Clock m_clock;


/*
 * A graphical representation of streaming in general (disregarding FEC):
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
 * as needed, covering any number of packets required, while requiring an
 * acceptable amount of performance loss compared to RS-codes, and offering
 * optimal use of the channel and lower latency compared to ARQ-based approaches.
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
 * The targetted loss rate may not be achieveable within the given channel,
 * but Wirehair/RaptorQ schemes allow you to finely tune the code "rate" to
 * match exactly what is needed as noted in the above paper.
 *
 * It seems like the best rate should be selected by evaluating equation (3)
 * with several exponents until the estimated loss rate matches the targetted
 * loss rate.  Faster approaches are feasible though unnecessary for evaulation.
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
static const int MAX_CHUNK_SIZE = 1400;
static const int PROTOCOL_OVERHEAD = 1 + 2 + 2;
static const int MAX_PROTOCOL_OVERHEAD = PROTOCOL_OVERHEAD + calico::Calico::OVERHEAD;
static const int MAX_PKT_SIZE = MAX_CHUNK_SIZE + MAX_PROTOCOL_OVERHEAD;
static const int PONG_SIZE = 1 + 4 + 4;



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
	// Returns number of bytes actually read or 0 for end of data
	virtual int ReadData(void *buffer, int max_bytes) = 0;

	// Data to send to remote host
	virtual void SendData(void *buffer, int bytes) = 0;
};




struct SourceSettings {
	float min_loss;				// [0..1] packetloss probability lower limit
	int min_delay, max_delay;	// Milliseconds clamp values for delay estimation
	int buffer_time;			// Milliseconds of buffering
	int chunk_size;				// Bytes per data chunk
	IDataSource *source;		// Data source
};




class BrookSource {
	SourceSettings _settings;

	calico::Calico _cipher;

	wirehair::Encoder _encoder;

	DelayEstimator _delay;
	LossEstimator _loss;

	// Calculated symbol rate from loss
	u32 _check_symbols_max;
	float _check_symbols_per_ms;

	// Last time we had a tick
	u32 _last_tick;
	bool _has_symbols;
	u32 _input_symbol;
	u32 _check_symbol;
	u8 _code_group;

	// Swap times for each code group for RTT calculation
	u32 _group_stamps[256];

	// Buffer of original data being sent for next swap
	vector<u8> _buffer;

	// Calculated interval from delay
	u32 _swap_interval;

	// Next time to trigger a swap
	u32 _swap_trigger;

	// Setup encoder on buffered data
	void Swap() {
		if (_buffer.size() <= 0) {
			_has_symbols = false;
		} else {
			_has_symbols = true;

			// NOTE: After this function call, the input data can be safely modified so long
			// as Encode() requests come after the original data block count.
			CAT_ENFORCE(!_encoder.BeginEncode(&_buffer[0], _buffer.size(), _settings.chunk_size));

			// Start symbols right after original data
			_check_symbol = _encoder.BlockCount();

			CAT_ENFORCE(_check_symbol == _input_symbol);
		}

		// File under next code group either way
		++_code_group;
	}

	// Send a check symbol
	void SendCheckSymbol() {
		const u16 block_count = _encoder.BlockCount();

		CAT_ENFORCE(_check_symbol >= block_count);

		u8 buffer[MAX_PKT_SIZE];

		// Prepend the code group
		buffer[0] = _code_group;

		// Add low bits of check symbol number
		*(u16*)(buffer + 1) = getLE((u16)_check_symbol);

		// Add block count
		*(u16*)(buffer + 1 + 2) = getLE(block_count);

		// FEC encode
		u32 bytes = _encoder.Encode(_check_symbol, buffer + PROTOCOL_OVERHEAD);

		// Encrypt
		bytes = _cipher.Encrypt(buffer, bytes + PROTOCOL_OVERHEAD, buffer, sizeof(buffer));

		// Transmit
		_settings.source->SendData(buffer, bytes);

		// Next check symbol
		++_check_symbol;
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
	// On startup:
	bool Initialize(const u8 key[SKEY_BYTES], const SourceSettings &settings) {
		if (_cipher.Initialize(key, "BROOK", calico::RESPONDER)) {
			return false;
		}

		_settings = settings;

		_delay.Initialize(_settings.min_delay, _settings.max_delay);
		_loss.Initialize(_settings.min_loss);

		_has_symbols = false;
		_last_tick = 0;
		_code_group = 0;
		_input_symbol = 0;
		_check_symbol = 0;

		CAT_OBJCLR(_group_stamps);

		CalculateInterval();
		CalculateRate();

		CAT_ENFORCE(_settings.chunk_size <= MAX_CHUNK_SIZE);
	}

	// Called once per tick, send all pending data and check symbols, providing
	// a timestamp in milliseconds
	void Tick(u32 ms) {
		// If it is time to swap the buffer,
		if ((s32)(ms - _swap_trigger) > 0) {
			_swap_trigger = ms + _swap_interval;

			Swap();
		}

		// Calculate tick interval
		u32 tick_interval = ms - _last_tick;

		// Read data in chunks
		u8 buffer[MAX_PKT_SIZE];
		u8 *data = buffer + PROTOCOL_OVERHEAD;
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
		}

		if (_has_symbols) {
			// Calculate number of check symbols to send based on rate
			u32 check_symbols = _check_symbols_per_ms * tick_interval;
			if (check_symbols > _check_symbols_max) {
				check_symbols = _check_symbols_max;
			}

			for (int ii = 0; ii < check_symbols; ++ii) {
				SendCheckSymbol();
			}
		}

		_last_tick = ms;
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
	// Called with null to indicate that data could not be recovered for this block
	virtual void OnPacket(void *packet) = 0;

	// Data to send to remote host
	virtual void SendData(void *buffer, int bytes) = 0;
};


struct SinkSettings {
	int chunk_size;
	IDataSink *sink;
};


struct Packet : BatchHead {
	// Block ID for this packet
	u32 id;

	// Data follows (settings.chunk_size bytes)
	u8 data[1];
};


struct CodeGroup {
	// Is code group open?
	bool open;

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

	void Open() {
		open = true;
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

	void AddPassed(Packet *p) {
		// Insert at head
		if (passed_head) {
			p->batch_next = passed_head;
		} else {
			passed_head = passed_tail = p;
		}
		passed_head = p;
	}

	void AddRecovery(Packet *p) {
		// Insert at head
		if (recovery_head) {
			p->batch_next = recovery_head;
		} else {
			recovery_head = recovery_tail = p;
		}
		recovery_head = p;
	}

	void AddOOS(Packet *p) {
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
			oos_tail->next = p;
			p->batch_next = 0;
			oos_tail = p;
			return;
		}

		// Search for insertion point from front, shooting for O(1)
		Packet *prev = 0, *next;
		for (next = oos_head; next; next = oos->batch_next) {
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


class BrookSink {
	SinkSettings _settings;

	calico::Calico _cipher;

	wirehair::Encoder _encoder;

	// Has any symbols to decode?
	bool _has_symbols;

	// Next expected (code group, block id)
	// Will be passed directly to IDataSink when received
	u32 _next_group, _next_id;

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
		_seen = 0;
		_count = 0;

		// Encrypt pong
		int len = _cipher.Encrypt(pkt, PONG_SIZE, pkt, sizeof(pkt));

		CAT_DEBUG_ENFORCE(len == sizeof(pkt));

		// Send it
		_settings.sink->SendData(pkt, len);
	}

	// Close off a code group and stop accepting symbols
	void CloseGroup(int code_group) {
		group->open = false;

		// Free allocated packet memory O(1)
		_allocator.ReleaseBatch(BatchSet(group->passed_head, group->passed_tail));
		_allocator.ReleaseBatch(BatchSet(group->oos_head, group->oos_tail));
		_allocator.ReleaseBatch(BatchSet(group->recovery_head, group->recovery_tail));
	}

	Packet *AllocatePacket() {
		return _allocator.AcquireObject<Packet>();
	}

	void FreePacket(Packet *p) {
		BatchSet bs(p);
		_allocator.ReleaseBatch(bs);
	}

public:
	// On startup:
	bool Initialize(const u8 key[SKEY_BYTES], const SinkSettings &settings) {
		if (_cipher.Initialize(key, "BROOK", calico::INITIATOR)) {
			return false;
		}

		_settings = settings;

		_has_symbols = false;

		// Expect (0, 0) first
		_next_group = 0;
		_next_id = 0;

		// Initialize the packet allocator
		_allocator.Initialize(sizeof(Packet)-1 + _settings.chunk_size);
	}

	// On packet received
	void Recv(u8 *pkt, int len) {
		u64 iv;
		len = _cipher.Decrypt(pkt, len, iv);

		// If packet may be valid,
		if (len > PROTOCOL_OVERHEAD) {
			// Read packet data
			u8 code_group = pkt[0];
			u32 id = getLE(*(u16*)(pkt + 1));
			u16 block_count = getLE(*(u16*)(pkt + 1 + 2));
			u8 *data = pkt + PROTOCOL_OVERHEAD;

			// Reconstruct block id
			id = ReconstructCounter<16, u32>(_largest_id[code_group], id);

			// If it is next in sequence,
			if (code_group == _next_group && id == _next_id) {
				// Pass it along
				_settings.sink->OnPacket(data);

				// Increment ID
				_next_id++;

				// TODO: Walk stored packets and pass along next if we already have it
			}

			// If it is original data,
			if (block_count == 0) {
				// Increment the original count
				_original_count[code_group]++;
			} else {
				// If we have enough data to start recovery process,
			}

			// Store it in case we need it as recovery data
			Packet *p = AllocatePacket();
			p->id = id;
			memcpy(p->data, data, _settings.chunk_size);

			// Add to front of linked list
			p->batch_next = _packet_buffer[code_group];
			_packet_buffer[code_group] = p;

			// Pong first packet of each group
			if (id == 0 && block_count == 0) {
				SendPong(code_group);
			}

			// TODO: Implement IV-based packet-loss estimator
			// TODO: Implement decoder time-based buffering

			if (_has_symbols) {
			} else {
			}
		}
	}
};









int main()
{
	m_clock.OnInitialize();

	m_clock.OnFinalize();

	return 0;
}


// TODO: Test it!

