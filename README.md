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

Your C++ code should have a class instance that derives from IShorthair and
implements its interface:

~~~
	// Called with the latest data packet from remote host
	virtual void OnPacket(u8 *packet, int bytes);

	// Called with the latest OOB packet from remote host
	virtual void OnOOB(u8 *packet, int bytes);

	// Send raw data to remote host over UDP socket
	virtual void SendData(u8 *buffer, int bytes);
~~~


#### Thread-Safety

It is safe to call `Send` and `SendOOB` from any thread.

The same thread that calls `Recv` should also be calling `Tick`.


#### Features:

+ Uses fastest, smallest Reed-Solomon codec available (Longhair).
+ Full-duplex communication over a lossy channel.
+ Adds a dial to control packet loss to any acceptable rate for applications over UDP.
+ Calculates and generates precisely the amount of redundancy required to achieve the target loss rate.
+ It supports variable-length data packets.
+ Overhead is 5 bytes/packet.
+ Does not require multiple threads.
+ Library has a clean platform-independent interface with minimal configuration required.


#### Credits

Software by Christopher A. Taylor mrcatid@gmail.com

Please reach out if you need support or would like to collaborate on a project.


