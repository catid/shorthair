#include "wirehair/Wirehair.hpp"
#include "Clock.hpp"
#include "MersenneTwister.hpp"
using namespace cat;

#include <iostream>
#include <iomanip>
#include <fstream>
#include <cmath>
using namespace std;

static Clock m_clock;


static int UDP_PAYLOAD = 1441;

struct Packet {
	u32 trigger;

	u8 buffer[UDP_PAYLOAD];

	Packet *next;
};



// Event-driven one-way channel simulator
// Attempt at realistic latency
// Uniformly distributed packetloss

class Channel {
	MersenneTwister _rng;		// RNG

	float _drop_rate;			// Ploss [0..1]

	float _lag_min;				// ms
	float _lag_avg; 			// ms
	float _lag_sig;	 			// sigma = sqrt(variance), 2sigma = 95% confidence interval

	u32 _ms;					// Simulation time (ms)
	PacketDelegate _delegate;

	Packet *_head, *_tail;

	bool DropPacket() {
		return _rng.Uni() < _drop_rate;
	}

	u32 NextDelay() { // ms
		// Based on http://www.ieee-infocom.org/2004/papers/37_4.pdf
		float x = _rng.Nor() * _lag_sig + _lag_avg;
		if (x < _lag_min) {
			x = _lag_min;
		}
		return (u32)x;
	}

public:
	// void OnPacket(Packet *p);
	typedef Delegate1<void, Packet *> PacketDelegate;

	void Initialize(u32 seed, float drop_percentage, float lag_avg, float lag_two_sig, float lag_min, PacketDelegate delegate) {
		_rng.Initialize(seed);

		_drop_rate = drop_percentage / 100.f;

		_lag_avg = lag_avg;
		_lag_sig = lag_two_sig / 2.f;
		_lag_min = lag_min;

		_ms = 0;
		_delegate = delegate;
		_head = _tail = 0;
	}

	// Advance the simulation ahead to the given number of ms and dequeue any events that occurred
	void AdvanceSimulation(u32 ms) {
		_ms = ms;

		// Peel off expired messages
		Packet *next = _head;
		for (Packet *p = next; p && p->trigger >= ms; p = next) {
			next = p->next;
			_delegate(p);
		}
		_head = next;
		if (!next) {
			_tail = 0;
		}
	}

	// Free a packet
	void FreePacket(Packet *p) {
		// TODO: Optimize with a custom memory allocator
		delete p;
	}

	// Get a new packet buffer with a prescribed delivery time
	// Or returns null when a packet got dropped
	Packet *NextPacket() {
		// If a packet got dropped,
		if (DropPacket()) {
			// Return null
			return 0;
		}

		// TODO: Optimize with a custom memory allocator
		Packet *np = new Packet;

		u32 trigger = _ms + NextDelay();
		np->trigger = trigger;

		// If should be added after tail,
		Packet *prev = 0;
		if (_tail && trigger < _tail->trigger) {
			for (Packet *p = _head; p; prev = p, p = p->next) {
				if (trigger < p->trigger) {
					if (prev) {
						prev->next = np;
					} else {
						_head = np;
					}
					np->next = p;
					return np;
				}
			}
		} else {
			prev = _tail;
		}

		if (prev) {
			prev->next = np;
		} else {
			_head = np;
		}
		np->next = 0;
		_tail = np;
		return np;
	}
};


















int main()
{
	MersenneTwister::InitializeNor();
	MersenneTwister::InitializeExp();
	m_clock.OnInitialize();

	Channel ch;
	ch.Initialize(0, 2, 210, 50, 200);

	for (;;) {
		cout << ch.NextDelay() << endl;
	}

	//FindBadDenseSeeds();

	for (int ii = 43; ii <= 64000; ii += 1000)
	{
		int block_count = ii;
		int block_bytes = 1300;
		int message_bytes = block_bytes * block_count;
		u8 *message = new u8[message_bytes];
		u8 *message_out = new u8[message_bytes];
		u8 *block = new u8[block_bytes];

		for (int ii = 0; ii < message_bytes; ++ii)
		{
			message[ii] = ii;
		}

		wirehair::Encoder encoder;

		double start = m_clock.usec();
		wirehair::Result r = encoder.BeginEncode(message, message_bytes, block_bytes);
		double end = m_clock.usec();

		if (r)
		{
			cout << "-- FAIL! N=" << encoder.BlockCount() << " encoder.BeginEncode error " << wirehair::GetResultString(r) << endl;
			cin.get();
			continue;
		}
		else
		{
			double mbytes = message_bytes / 1000000.;

			cout << ">> OKAY! N=" << encoder.BlockCount() << "(" << mbytes << " MB) encoder.BeginEncode in " << end - start << " usec, " << message_bytes / (end - start) << " MB/s" << endl;
			//cin.get();
		}

		Abyssinian prng;
		cat::wirehair::Decoder decoder;

		u32 overhead_sum = 0, overhead_trials = 0;
		u32 drop_seed = 50002;
		double time_sum = 0;
		const int trials = 1000;
		for (int jj = 0; jj < trials; ++jj)
		{
			int blocks_needed = 0;

			wirehair::Result s = decoder.BeginDecode(message_out, message_bytes, block_bytes);
			if (s)
			{
				cout << "-- FAIL! N=" << decoder.BlockCount() << " decoder.BeginDecode error " << wirehair::GetResultString(s) << endl;
				cin.get();
				return 1;
			}

			prng.Initialize(drop_seed);
			for (u32 id = 0;; ++id)
			{
				if (prng.Next() & 1) continue;
				encoder.Encode(id, block);

				++blocks_needed;
				double start = m_clock.usec();
				wirehair::Result r = decoder.Decode(id, block);
				double end = m_clock.usec();

				if (r != wirehair::R_MORE_BLOCKS)
				{
					if (r == wirehair::R_WIN)
					{
						u32 overhead = blocks_needed - decoder.BlockCount();
						overhead_sum += overhead;
						++overhead_trials;

						//cout << ">> OKAY! N=" << decoder.BlockCount() << " decoder.Decode in " << end - start << " usec, " << message_bytes / (end - start) << " MB/s after " << overhead << " extra blocks.  Average extra = " << overhead_sum / (double)overhead_trials << ". Seed = " << drop_seed << endl;
						time_sum += end - start;

						if (!memcmp(message, message_out, message_bytes))
						{
							//cout << "Match!" << endl;
						}
						else
						{
							cout << "FAAAAAIL! Seed = " << drop_seed << endl;

							for (int ii = 0; ii < message_bytes; ++ii)
							{
								if (message_out[ii] != message[ii])
									cout << ii << " : " << (int)message_out[ii] << endl;
							}

							cin.get();
						}
					}
					else
					{
						cout << "-- FAIL!  N=" << decoder.BlockCount() << " decoder.Decode error " << wirehair::GetResultString(r) << " from drop seed " << drop_seed << endl;

						overhead_sum += 1;
						++overhead_trials;

						//cin.get();
					}

					//cin.get();
					break;
				}
			}

			++drop_seed;
		}

		double avg_time = time_sum / trials;
		double avg_overhead = overhead_sum / (double)overhead_trials;
		double avg_bytes = message_bytes * (decoder.BlockCount() + avg_overhead) / (double)decoder.BlockCount() - message_bytes;
		cout << "N=" << decoder.BlockCount() << " decoder.Decode in " << avg_time << " usec, " << message_bytes / avg_time << " MB/s.  Average overhead = " << avg_overhead << " (" << avg_bytes << " bytes)" << endl;
	}

	m_clock.OnFinalize();

	return 0;
}

