# Shorthair Low-Latency Networking

Shorthair is a portable C++ library uses the [Longhair library](https://github.com/catid/longhair) to provide low-latency loss-recovery, which uses extra bandwidth to make almost any unreliable packet channel suitable for real-time communication.

Erasure codes in software are fast with low-overhead.

Advantages of using erasure codes in online games:

+ > 50% faster delivery over UDP than over TCP
+ > 50% less bandwidth used than naive redundancy
+ > 50% better recovery rate than parity redundancy

Improves the experience for multiplayer mobile apps.

Please take a look at my presentation on Erasure codes for more motivation:
[Erasure Codes in Software](https://github.com/catid/shorthair/blob/master/docs/ErasureCodesInSoftware.pdf)


#### Usage

It is designed for applications that send no more than 2000 packets per second (about 2 MB/s).  Beyond that, it will hit asserts and not be able to protect the traffic.

Step 1: Add the source code to your project.  #include "Shorthair.hpp"

Step 2: Your C++ code should have a class instance that derives from IShorthair and
implements its interface:

~~~
class MyClass : public IShorthair
{
	void OnPacket(u8 *packet, int bytes) override
	{
		// Called with the latest data packet from remote host
	}

	void OnOOB(u8 *packet, int bytes) override
	{
		// Called with the latest OOB packet from remote host
	}

	void SendData(u8 *buffer, int bytes) override
	{
		// Send raw data to remote host over UDP socket
	}
...
~~~

Step 3: Create a Shorthair object on the server and client side.  Initialize it with some settings for your application:

~~~
    cat::shorthair::ShorthairCodec CodecObject;

    Settings settings;
    settings.min_fec_overhead = 0.1f; // 10%+
    settings.max_delay = 100; // 100 milliseconds
    settings.max_data_size = 1400; // Normal UDP packet
    settings.interface_ptr = &myClass; // Pointer to IShorthair object

    CodecObject.Initialize(settings);
~~~

Step 4: When sending a FEC-protected packet, call the `ShorthairCodec::Send` method.  When sending an unprotected packet, call the `ShorthairCodec::SendOOB()` method:

~~~
    char message[3] = {};
    CodecObject.Send(message, sizeof(message));
~~~

Packets sent with `Send` can still be duplicated by the network, but they will be protected by FEC and be much less likely to be lost.

~~~
    char message[3] = {};
    CodecObject.SendOOB(message, sizeof(message));
~~~

Packets sent with `SendOOB` will not be protected by FEC.  It is appropriate to send statistics and data that changes every packet with `SendOOB`.

It's safe to call the Send functions from any thread.

Step 5: Periodically call `ShorthairCodec::Tick()`.  Around a 10-20 ms interval is best.

Step 6: When a packet is received, call `ShorthairCodec::Recv()` with the raw UDP packet data.

The ShorthairCodec object is not thread-safe, so be sure to hold a lock if multiple threads are using it.


#### Features:

+ Uses a fast Reed-Solomon codec: Longhair.
+ Full-duplex communication over a lossy channel.
+ Adds a dial to control packet loss to any acceptable rate for applications over UDP.
+ Calculates and generates precisely the amount of redundancy required to achieve the target loss rate.
+ It supports variable-length data packets.
+ Overhead is 5 bytes/packet.


#### Credits

Software by Christopher A. Taylor mrcatid@gmail.com

Please reach out if you need support or would like to collaborate on a project.


