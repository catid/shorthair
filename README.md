# Shorthair Low-Latency Networking in C++

Shorthair library uses the [Longhair library](https://github.com/catid/longhair) to provide low-latency loss-recovery, which uses extra bandwidth to make almost any unreliable packet channel suitable for real-time communication.

Erasure codes in software are fast with low-overhead.

Advantages of using erasure codes in online games:

+ > 50% faster delivery over UDP than over TCP
+ > 50% less bandwidth used than naive redundancy
+ > 50% better recovery rate than parity redundancy

Improves the experience for multiplayer mobile apps.

Please take a look at my presentation on Erasure codes for more motivation:
[Erasure Codes in Software](https://github.com/catid/shorthair/blob/master/docs/ErasureCodesInSoftware.pdf)

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

This software was written entirely by myself ( Christopher A. Taylor <mrcatid@gmail.com> ).  If you
find it useful and would like to buy me a coffee, consider [tipping](https://www.gittip.com/catid/).

