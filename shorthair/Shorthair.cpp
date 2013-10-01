/*
	Copyright (c) 2013 Christopher A. Taylor.  All rights reserved.

	Redistribution and use in source and binary forms, with or without
	modification, are permitted provided that the following conditions are met:

	* Redistributions of source code must retain the above copyright notice,
	  this list of conditions and the following disclaimer.
	* Redistributions in binary form must reproduce the above copyright notice,
	  this list of conditions and the following disclaimer in the documentation
	  and/or other materials provided with the distribution.
	* Neither the name of Shorthair nor the names of its contributors may be
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

#include "Shorthair.hpp"
#include "EndianNeutral.hpp"
#include "BitMath.hpp"
using namespace cat;
using namespace shorthair;

#include <cmath>
using namespace std;

#define CAT_DUMP_SHORTHAIR

#ifdef CAT_DUMP_SHORTHAIR
#include <iostream>
#include <iomanip>
using namespace std;
#endif

#if defined(CAT_DUMP_SHORTHAIR)
#define CAT_IF_DUMP(x) x
#else
#define CAT_IF_DUMP(x)
#endif


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
 * Wirehair improves on this, allowing us to use only as much bandwidth as
 * needed, covering any number of packets required.  These are "rateless" codes
 * that require an acceptable amount of performance loss compared to RS-codes,
 * and offering optimal use of the channel and lower latency compared to
 * ARQ-based approaches.
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
 * Shorthair Protocol
 *
 * Source -> Sink data packet format:
 *
 * <OOB[1 bit = 0] | group[7 bits]> (brook-wirehair) : Out of band flag = 0
 * <block count[2 bytes]> (brook-wirehair)
 * <block id[2 bytes]> (brook-wirehair)
 * <block size[2 bytes]> (brook: Only for recovery packets)
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
 * Total overhead = 16 bytes per original packet.
 *
 *
 * Sink -> Source out-of-band packet format:
 *
 * <OOB[1 bit = 1] | group[7 bits]> : Out of band flag = 1
 * <packet type[1 byte]>
 *
 * Packet types:
 * group = input group
 * <packet type[1 byte] = 0xff>
 * <seen count[4 bytes]>
 * <total count[4 bytes]>
 *
 * This message is sent in reaction to a new code group on the receipt of the
 * first original data packet to update the source's redundancy in reaction to
 * measured packet loss as seen at the sink and to measure the round-trip time
 * for deciding how often to switch codes.
 *
 *
 * Out of band types are delivered to your callback.
 */

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

int CalculateApproximate(double p, int n, double Qtarget) {
	double q;
	u32 r;

	// TODO: Merge this with upstream stuff on the laptop
	if (n <= 0) {
		return 0;
	}

	// O(log(N))-time calculator

	// Identify fast 2^i upper bound on required r
	for (r = 1; r; r <<= 1) {
		q = NormalApproximation(n, r, p);

		// If this approximation is close,
		if (q < Qtarget) {
			break;
		}
	}

	// If r-1 is also good,
	if (NormalApproximation(n, r - 1, p) < Qtarget) {
		// Trial-flip bits off from high to low:
		for (u32 s = r-- >> 1; s > 0; s >>= 1) {
			// Flip next bit down
			u32 t = r ^ s;

			// If this bit was not needed,
			if (NormalApproximation(n, t, p) < Qtarget) {
				// Shave it off
				r = t;
			}
		}
	}

	++r;

	return r;
}

/*
 * Incorporating the non-ideality of the code:
 *
 * let:
 * 	Pr = probability of recovery failure with n of n random symbols ~= 3%
 *
 * Recall p(r) = probability of losing r packets so only n random packets left
 *
 * Perceived loss = q + sum( p(l) * (n+r, l) * (1 - Pr) ^ (1 + r - l) ; l = 1..r )
 */

/*
 * Solving the equations exactly
 *
 * We want to solve the above equation for r with a given {p, Pr, n, Qtarget}
 * so that q < Qtarget.
 *
 * The equations are not amenable to logarithmic inversion, so a numerical
 * approach is taken.
 *
 * The binomial formula verifies that the first sum from 0..n+r is equal to 1,
 * and computing q with the complement is more efficient with fewer terms:
 *
 * q = 1 - sum( p(l) * (n+r, l) ; l = 0..r ) + sum(...)
 *
 * Combining the two sums provides a succinct expression for q:
 *
 * q = 1 - p(0) - sum( p(l) * (n+r, l) - p(l) * (n+r, l) * (1 - Pr) ^ (1 + r - l) ; l = 1..r )
 *
 * q = 1 - sum( p^l * (1-p)^(n+r-l) * (n+r, l) * (1 - (1-Pr) ^ (1+r-l)) ; l = 1..r ) - (1-p)^(n+r)
 *            (term1)    (term2)      (term3)         (term4)                           (term5)
 *
 * Computing from l = r..1 is more efficient since the exponentiations can be
 * built up iteratively.
 *
 * term1: computed in a table and then reverse-indexed, reused.
 * term2: computed iteratively for each l from the previous one after (1-p)^n is precomputed.
 * term3: computed via logarithm.
 * term4: computed iteratively for each l from the previous one.
 * term5: same as term2.
 *
 * Computing term 3:
 *
 * exp log (n+r, l) = exp log (n+r)! / (l! * (n+r-l)!) = exp ( log (n+r)! - log l! - log (n+r-l)! )
 *
 * The numerator is fixed so we can reuse it, but the denominator needs to be
 * recalculated repeatedly.  log x! has an efficient approximation for large x
 * and can be tabulated for small x.
 *
 */

#define PI 3.1415926535897932384626433832795

static const double LOG2PI = 0.5 * log(2 * PI);

static double LF[] = {
	0.000000000000000,
	0.000000000000000,
	0.693147180559945,
	1.791759469228055,
	3.178053830347946,
	4.787491742782046,
	6.579251212010101,
	8.525161361065415,
	10.604602902745251,
	12.801827480081469,
	15.104412573075516,
	17.502307845873887,
	19.987214495661885,
	22.552163853123421,
	25.191221182738683,
	27.899271383840894,
	30.671860106080675,
	33.505073450136891,
	36.395445208033053,
	39.339884187199495,
	42.335616460753485,
	45.380138898476908,
	48.471181351835227,
	51.606675567764377,
	54.784729398112319,
	58.003605222980518,
	61.261701761002001,
	64.557538627006323,
	67.889743137181526,
	71.257038967168000,
	74.658236348830158,
	78.092223553315307,
	81.557959456115029,
	85.054467017581516,
	88.580827542197682,
	92.136175603687079,
	95.719694542143202,
	99.330612454787428,
	102.968198614513810,
	106.631760260643450,
	110.320639714757390,
	114.034211781461690,
	117.771881399745060,
	121.533081515438640,
	125.317271149356880,
	129.123933639127240,
	132.952575035616290,
	136.802722637326350,
	140.673923648234250,
	144.565743946344900,
	148.477766951773020,
	152.409592584497350,
	156.360836303078800,
	160.331128216630930,
	164.320112263195170,
	168.327445448427650,
	172.352797139162820,
	176.395848406997370,
	180.456291417543780,
	184.533828861449510,
	188.628173423671600,
	192.739047287844900,
	196.866181672889980,
	201.009316399281570,
	205.168199482641200,
	209.342586752536820,
	213.532241494563270,
	217.736934113954250,
	221.956441819130360,
	226.190548323727570,
	230.439043565776930,
	234.701723442818260,
	238.978389561834350,
	243.268849002982730,
	247.572914096186910,
	251.890402209723190,
	256.221135550009480,
	260.564940971863220,
	264.921649798552780,
	269.291097651019810,
	273.673124285693690,
	278.067573440366120,
	282.474292687630400,
	286.893133295426990,
	291.323950094270290,
	295.766601350760600,
	300.220948647014100,
	304.686856765668720,
	309.164193580146900,
	313.652829949878990,
	318.152639620209300,
	322.663499126726210,
	327.185287703775200,
	331.717887196928470,
	336.261181979198450,
	340.815058870798960,
	345.379407062266860,
	349.954118040770250,
	354.539085519440790,
	359.134205369575340,
	363.739375555563470,
	368.354496072404690,
	372.979468885689020,
	377.614197873918670,
	382.258588773060010,
	386.912549123217560,
	391.575988217329610,
	396.248817051791490,
	400.930948278915760,
	405.622296161144900,
	410.322776526937280,
	415.032306728249580,
	419.750805599544780,
	424.478193418257090,
	429.214391866651570,
	433.959323995014870,
	438.712914186121170,
	443.475088120918940,
	448.245772745384610,
	453.024896238496130,
	457.812387981278110,
	462.608178526874890,
	467.412199571608080,
	472.224383926980520,
	477.044665492585580,
	481.872979229887900,
	486.709261136839360,
	491.553448223298010,
	496.405478487217580,
	501.265290891579240,
	506.132825342034830,
	511.008022665236070,
	515.890824587822520,
	520.781173716044240,
	525.679013515995050,
	530.584288294433580,
	535.496943180169520,
	540.416924105997740,
	545.344177791154950,
	550.278651724285620,
	555.220294146894960,
	560.169054037273100,
	565.124881094874350,
	570.087725725134190,
	575.057539024710200,
	580.034272767130800,
	585.017879388839220,
	590.008311975617860,
	595.005524249382010,
	600.009470555327430,
	605.020105849423770,
	610.037385686238740,
	615.061266207084940,
	620.091704128477430,
	625.128656730891070,
	630.172081847810200,
	635.221937855059760,
	640.278183660408100,
	645.340778693435030,
	650.409682895655240,
	655.484856710889060,
	660.566261075873510,
	665.653857411105950,
	670.747607611912710,
	675.847474039736880,
	680.953419513637530,
	686.065407301994010,
	691.183401114410800,
	696.307365093814040,
	701.437263808737160,
	706.573062245787470,
	711.714725802289990,
	716.862220279103440,
	722.015511873601330,
	727.174567172815840,
	732.339353146739310,
	737.509837141777440,
	742.685986874351220,
	747.867770424643370,
	753.055156230484160,
	758.248113081374300,
	763.446610112640200,
	768.650616799717000,
	773.860102952558460,
	779.075038710167410,
	784.295394535245690,
	789.521141208958970,
	794.752249825813460,
	799.988691788643450,
	805.230438803703120,
	810.477462875863580,
	815.729736303910160,
	820.987231675937890,
	826.249921864842800,
	831.517780023906310,
	836.790779582469900,
	842.068894241700490,
	847.352097970438420,
	852.640365001133090,
	857.933669825857460,
	863.231987192405430,
	868.535292100464630,
	873.843559797865740,
	879.156765776907600,
	884.474885770751830,
	889.797895749890240,
	895.125771918679900,
	900.458490711945270,
	905.796028791646340,
	911.138363043611210,
	916.485470574328820,
	921.837328707804890,
	927.193914982476710,
	932.555207148186240,
	937.921183163208070,
	943.291821191335660,
	948.667099599019820,
	954.046996952560450,
	959.431492015349480,
	964.820563745165940,
	970.214191291518320,
	975.612353993036210,
	981.015031374908400,
	986.422203146368590,
	991.833849198223450,
	997.249949600427840,
	1002.670484599700300,
	1008.095434617181700,
	1013.524780246136200,
	1018.958502249690200,
	1024.396581558613400,
	1029.838999269135500,
	1035.285736640801600,
	1040.736775094367400,
	1046.192096209724900,
	1051.651681723869200,
	1057.115513528895000,
	1062.583573670030100,
	1068.055844343701400,
	1073.532307895632800,
	1079.012946818975000,
	1084.497743752465600,
	1089.986681478622400,
	1095.479742921962700,
	1100.976911147256000,
	1106.478169357800900,
	1111.983500893733000,
	1117.492889230361000,
	1123.006317976526100,
	1128.523770872990800,
	1134.045231790853000,
	1139.570684729984800,
	1145.100113817496100,
	1150.633503306223700,
	1156.170837573242400
};

double LogFactorial(int n) {
	// Code from http://www.johndcook.com/csharp_log_factorial.html

	if (n < 255) {
		CAT_ENFORCE(n >= 0);
		return LF[n];
	}

	// Stirling's approximation
	double x = n + 1;
	return (x - 0.5) * log(x) - x + LOG2PI + 1. / (12. * x);
}

int CalculateExact(double p, int n, double Pr, double Qtarget) {
	// Repeated from above:
	// q = 1 - sum( p^l * (1-p)^(n+r-l) * (n+r, l) * (1 - (1-Pr) ^ (1+r-l)) ; l = 1..r ) - (1-p)^(n+r)
	//            (term1)    (term2)      (term3)         (term4)                           (term5)

	// Calculate complement of p: Probability of receiving a packet
	double pc = 1. - p;

	// Calculate complement of Pr: Probability of decoding with n/n random blocks
	double Prc = 1. - Pr;

	// Stored results
	vector<double> lfl;		// [i] = log i!

	// p ^ l
	double pel = p;
	vector<double> term1;	// [i] = p ^ i
	term1.push_back(1.);	// p ^ 0 = 1

	// Compute (1 - p) ^ n using square-and-multiply optimization
	double pcn = 1.;
	int msb = 1 << BSR32(n);
	while (msb) {
		pcn *= pcn;
		if (n & msb) {
			pcn *= pc;
		}
		msb >>= 1;
	}

	// (1 - p) ^ n ^ (r - l)
	vector<double> term2;	// [i] = (1-p) ^ (n + i), i = r - l
	term2.push_back(pcn);	// (1-p) ^ (n + 0)

	// term3: log l! part
	vector<double> term3;
	term3.push_back(0);

	// (1 - Pr) ^ (1 + r-l)
	double prn = Prc;
	vector<double> term4;
	term4.push_back(prn);	// (1 - Pr) ^ (1 + 0) = 1 - Pr

	// For each value of r,
	int r = 0;
	double q;
	do {
		++r;

		// If redundancy is taking too long to calculate,
		if (r >= 50) {
			// Give up here
			return CalculateApproximate(p, n, Qtarget);
		}

		// Number of total packets, including original and recovery packets
		const int m = n + r;

		// Populate term1
		term1.push_back(pel);
		pel *= p;

		// Populate term2
		pcn *= pc;
		term2.push_back(pcn);

		// Populate term3
		term3.push_back(LogFactorial(r));

		// Populate term4
		prn *= Prc;
		term4.push_back(prn);

		q = 1.;

		// Calculate log m!
		double lfm = LogFactorial(m);

		// For each l,
		for (int l = 1; l <= r; ++l) {
			// Calculate log (n+r-l)!
			double lfml = LogFactorial(m - l);

			// Calculate term3: (n+r, l)
			double ncr = exp(lfm - term3[l] - lfml);

			// Remove term
			q -= term1[l] * term2[r - l] * ncr * (1 - term4[r - l]);
		}

		// term5
		q -= term2[r];
	} while (q >= Qtarget);

	return r;
}

int CalculateRedundancy(double p, int n, double Qtarget) {
	// If in region where approximation works,
	if (((n * p >= 10. &&
		n * (1 - p) >= 10.))) {
		return CalculateApproximate(p, n, Qtarget);
	} else {
		return CalculateExact(p, n, 0.97, Qtarget);
	}
}


//// LossEstimator

void LossEstimator::Initialize(float min_loss, float max_loss) {
	_index = 0;
	_count = 0;
	_min_loss = min_loss;
	_max_loss = max_loss;
	_loss = min_loss;
}

void LossEstimator::Insert(u32 seen, u32 count) {
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

void LossEstimator::Calculate() {
	const int len = _count;
	u64 seen = 0, count = 0;

	for (int ii = 0; ii < len; ++ii) {
		seen += _bins[ii].seen;
		count += _bins[ii].count;
	}

	if (count > 0) {
		_loss = (float)((count - seen) / (double)count);

		// Clamp value
		if (_loss < _min_loss) {
			_loss = _min_loss;
		}
		if (_loss > _max_loss) {
			_loss = _max_loss;
		}
	} else {
		_loss = _min_loss;
	}

	// TODO: Validate that this is a good predictor
}


//// DelayEstimator

void DelayEstimator::Initialize(int min_delay, int max_delay) {
	_index = 0;
	_count = 0;
	_min_delay = min_delay;
	_max_delay = max_delay;
	_delay = min_delay;
}

void DelayEstimator::Insert(int delay) {
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

void DelayEstimator::Calculate() {
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


//// EncoderThread

bool EncoderThread::Entrypoint(void *param) {
	while (!_kill) {
		_wake_lock.Enter();
		if (!_kill) {
			Process();
		}
	}

	return true;
}

void EncoderThread::Process() {
	_processing_lock.Enter();

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
	for (Packet *p = _group_head; p; p = (Packet*)p->batch_next) {
		u16 len = p->len;

		CAT_ENFORCE(len <= chunk_size);

		// Start each block off with the 16-bit size
		*(u16*)buffer = getLE(len);
		buffer += 2;

		// Add packet data in
		memcpy(buffer, p->data + PROTOCOL_OVERHEAD, len);

		// Zero the high bytes
		CAT_CLR(buffer + len, chunk_size - len);

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

	_processing_lock.Leave();
}

void EncoderThread::Initialize(ReuseAllocator *allocator) {
	Finalize();

	_allocator = allocator;

	_kill = false;
	_last_garbage = false;
	_encoder_ready = false;
	_next_block_id = 0;
	_largest = 0;
	_block_count = 0;
	_sent_head = _sent_tail = 0;

	_wake_lock.Enter();

	StartThread();

	_initialized = true;
}

void EncoderThread::Finalize() {
	if (_initialized) {
		_kill = true;

		_wake_lock.Leave();

		WaitForThread();

		FreeGarbage();

		_initialized = false;
	}
}

Packet *EncoderThread::Queue(int len) {
	CAT_ENFORCE(len > 0);

	// Allocate sent packet buffer
	Packet *p = _allocator->AcquireObject<Packet>();
	p->batch_next = 0;
	p->len = len;

	// If this new packet is larger than the previous ones,
	if (_largest < len) {
		// Remember the largest size for when we start emitting check symbols
		_largest = len;
	}

	// Insert at end of list
	if (_sent_tail) {
		_sent_tail->batch_next = p;
	} else {
		_sent_head = p;
	}
	_sent_tail = p;

	++_block_count;

	CAT_ENFORCE(_block_count <= CAT_WIREHAIR_MAX_N);

	return p;
}

void EncoderThread::EncodeQueued() {
	if (_block_count <= 0) {
		return;
	}

	_processing_lock.Enter();

	// NOTE: After N = 1 case, next time encoding starts it will free the last one
	FreeGarbage();

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
	if (_group_count <= 1) {
		// Set up for special mode
		_encoder_ready = true;
		_group_block_size = _group_largest;

		_processing_lock.Leave();	
	} else {
		// Flag encoder as being busy processing previous data
		_encoder_ready = false;

		_processing_lock.Leave();	

		// Wake up the processing thread
		_wake_lock.Leave();
	}
}

// Returns 0 if recovery blocks cannot be sent yet
int EncoderThread::GenerateRecoveryBlock(u8 *buffer) {
	if (!_encoder_ready) {
		return 0;
	}

	// Get next block ID to send
	u32 block_id = _next_block_id++;

	// Add low bits of check symbol number
	*(u16*)buffer = getLE((u16)block_id);

	// Add block count
	*(u16*)(buffer + 2) = getLE((u16)_group_count);

	// If single packet,
	if (_group_count == 1) {
		// Copy original data directly
		memcpy(buffer + 4, _group_head->data + PROTOCOL_OVERHEAD, _group_block_size);
	} else {
		CAT_ENFORCE(_group_block_size == (int)_encoder.Encode(block_id, buffer + 4));

		FreeGarbage();
	}

	return 4 + _group_block_size;
}


//// CodeGroup

void CodeGroup::Open(u32 ms) {
	open = true;
	open_time = ms;
	largest_id = 0;
	block_count = 0;
	original_seen = 0;
	total_seen = 0;
	largest_len = 0;
	head = tail = 0;
	recovery_head = recovery_tail = 0;
}

void CodeGroup::Close(ReuseAllocator &allocator) {
	open = false;

	// Free allocated packet memory O(1)
	allocator.ReleaseBatch(BatchSet(head, tail));
	allocator.ReleaseBatch(BatchSet(recovery_head, recovery_tail));

	head = tail = 0;
	recovery_head = recovery_tail = 0;
}

void CodeGroup::AddRecovery(Packet *p) {
	// Insert at head
	if (!recovery_tail) {
		recovery_tail = p;
	}
	p->batch_next = recovery_head;
	recovery_head = p;
}

void CodeGroup::AddOriginal(Packet *p) {
	// Insert into empty list
	if (!head) {
		head = tail = p;
		p->batch_next = 0;
		return;
	}

	const u32 id = p->id;

	// Attempt fast O(1) insertion at end
	if (tail && id > tail->id) {
		// Insert at the end
		tail->batch_next = p;
		p->batch_next = 0;
		tail = p;
		return;
	}

	// Search for insertion point from front, shooting for O(1)
	Packet *prev = 0, *next;
	for (next = head; next; next = (Packet*)next->batch_next) {
		if (id < next->id) {
			break;
		}
	}

	// If inserting after prev,
	if (prev) {
		prev->batch_next = p;
	} else {
		head = p;
	}
	if (!next) {
		tail = p;
	}
	p->batch_next = next;
}


//// GroupFlags

void GroupFlags::ClearOpposite(const u8 group) {
	// Find current word
	int word = group >> 5;

	// Clear three opposite words, leaving the
	// two words ahead and behind alone:

	word += 3;
	word &= 7;
	u32 open = _open[word];
	if (open) {
		open &= ~_done[word];
		while (open) {
			// Find next bit index 0..31
			u32 msb = BSR32(open);

			// Calculate timeout group
			u8 timeout_group = (word << 5) | msb;

			OnGroupTimeout(timeout_group);

			// Clear the bit
			open ^= 1 << msb;
		}
	}
	_done[word] = 0;
	_open[word] = 0;

	++word;
	word &= 7;
	open = _open[word];
	if (open) {
		open &= ~_done[word];
		while (open) {
			// Find next bit index 0..31
			u32 msb = BSR32(open);

			// Calculate timeout group
			u8 timeout_group = (word << 5) | msb;

			OnGroupTimeout(timeout_group);

			// Clear the bit
			open ^= 1 << msb;
		}
	}
	_done[word] = 0;
	_open[word] = 0;

	++word;
	word &= 7;
	open = _open[word];
	if (open) {
		open &= ~_done[word];
		while (open) {
			// Find next bit index 0..31
			u32 msb = BSR32(open);

			// Calculate timeout group
			u8 timeout_group = (word << 5) | msb;

			OnGroupTimeout(timeout_group);

			// Clear the bit
			open ^= 1 << msb;
		}
	}
	_done[word] = 0;
	_open[word] = 0;
}


//// Shorthair : Encoder

// Send a check symbol
bool Shorthair::SendCheckSymbol() {
	u8 *buffer = _packet_buffer.get();
	int bytes = _encoder.GenerateRecoveryBlock(buffer + 1);

	// If no data to send,
	if (bytes <= 0) {
		// Abort
		return false;
	}

	// Prepend the code group
	buffer[0] = _code_group & 0x7f;

	// Encrypt
	bytes = _cipher.Encrypt(buffer, 1 + bytes, buffer, _packet_buffer.size());

	// Transmit
	_settings.interface->SendData(buffer, bytes);

	return true;
}

// Calculate interval from delay
void Shorthair::CalculateInterval() {
	int delay = _delay.Get();

	// From previous work: Ideal buffer size = delay + swap interval * 2

	// Reasoning: We want to be faster than TCP for recovery, and
	// ARQ recovery speed > 3x delay : data -> ack -> retrans
	// Usually there's a timeout also but let's pretend it's ideal ARQ.

	// Crazy idea:
	// So our buffer size should be 3x delay.
	// So our swap interval should be about equal to delay.

	// Note that if delay is long, we only really need to have a swap
	// interval long enough to cover burst losses so this may be an
	// upper bound for some cases of interest.

	// Idea: Give it at least 100 milliseconds of buffering before a swap
	if (delay < MIN_CODE_DURATION) {
		delay = MIN_CODE_DURATION;
	}

	_swap_interval = delay;
}

// From pong message, round-trip time
void Shorthair::UpdateRTT(int ms) {
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
void Shorthair::UpdateLoss(u32 seen, u32 count) {
	CAT_ENFORCE(seen <= count);

	if (count > 0) {
		_loss.Insert(seen, count);
		_loss.Calculate();
	}
}

void Shorthair::OnOOB(u8 *pkt, int len) {
	switch (pkt[1]) {
		case PONG_TYPE:
			if (len == PONG_SIZE) {
				u8 code_group = ReconstructCounter<7, u8>(_code_group, pkt[0] & 0x7f);
				u32 seen = getLE(*(u32*)(pkt + 2));
				u32 count = getLE(*(u32*)(pkt + 2 + 4));
				int rtt = _clock.msec() - _group_stamps[code_group];

				// Calculate RTT
				if (rtt >= 0) {
					// Compute updates
					UpdateRTT(rtt);
					UpdateLoss(seen, count);
				}

				CAT_IF_DUMP(cout << "PONG group = " << (int)code_group << " rtt = " << rtt << " seen = " << seen << " / count = " << count << " swap interval = " << _swap_interval << endl;)
			}
			break;
		default:
			// Pass unrecognized OOB data to the interface
			_settings.interface->OnOOB(pkt + 1, len - 1);
	}
}


//// Shorthair : Decoder

void Shorthair::RecoverGroup(CodeGroup *group) {
	// Allocate space for recovered packet
	Packet *temp = _allocator.AcquireObject<Packet>();
	temp->batch_next = 0;

	int block_count = group->block_count;
	u8 *data = temp->data;

	// Packet IDs are stored in order
	Packet *p = group->head;

	for (int ii = 0; ii < block_count; ++ii) {
		// If we already got that packet,
		if (p && p->id == (u32)ii) {
			// Advance to next packet we have
			p = (Packet*)p->batch_next;
		} else {
			// Reconstruct the block for the next expected ID
			_decoder.ReconstructBlock(ii, data);

			// Reconstruct data length
			int len = getLE(*(u16*)data);

			// Handle data ASAP
			_settings.interface->OnPacket(data + 2, len);
		}
	}

	_allocator.ReleaseBatch(temp);
}

// On receiving a data packet
void Shorthair::OnData(u8 *pkt, int len) {
	if (len <= PROTOCOL_OVERHEAD) {
		return;
	}

	// Read packet data
	u8 code_group = ReconstructCounter<7, u8>(_last_group, pkt[0]);
	CodeGroup *group = &_groups[code_group];
	_last_group = code_group;

	// If this group is already done,
	if (GroupFlags::IsDone(code_group)) {
		// Ignore more data received for this group
		return;
	}

	// If group is not open yet,
	if (!group->open) {
		// Open group
		group->Open(_clock.msec());
		GroupFlags::SetOpen(code_group);
		CAT_IF_DUMP(cout << "~~~~~~~~~~~~~~~~~~~~~ OPENING GROUP " << (int)code_group << endl;)
	}

	u32 id = getLE(*(u16*)(pkt + 1));
	u16 block_count = getLE(*(u16*)(pkt + 1 + 2));
	u8 *data = pkt + PROTOCOL_OVERHEAD;
	u16 data_len = (u16)(len - PROTOCOL_OVERHEAD);

	// If block count is not the largest seen for this group,
	if (block_count < group->block_count) {
		// Use the latest
		block_count = group->block_count;
	} else {
		// Update largest block count seen for group
		group->block_count = block_count;
	}

	// Reconstruct block id
	id = ReconstructCounter<16, u32>(group->largest_id, id);

	// Pong first packet of each group as fast as possible
	if (id == 0) {
		SendPong(code_group);
	}

	// If ID is the largest seen so far,
	if (id > group->largest_id) {
		// Update largest seen ID for decoding ID in next packet
		group->largest_id = id;
	}

	// If data length is the largest seen so far,
	if (data_len > group->largest_len) {
		// Use it for recovery
		group->largest_len = data_len;
	}

	// If packet contains original data,
	if (id < block_count) {
		// Process it immediately
		_settings.interface->OnPacket(data, data_len);

		// Increment original seen count
		group->original_seen++;
	}

	// If we know how many blocks to expect,
	if (group->largest_id >= block_count) {
		// If block count is special case 1,
		if (block_count == 1) {
			CAT_IF_DUMP(cout << "ONE RECEIVE : " << (int)code_group << endl;)
			// If have not processed the original block yet,
			if (group->original_seen == 0) {
				// Process it immediately
				_settings.interface->OnPacket(data, data_len);
			}

			group->Close(_allocator);
			GroupFlags::SetDone(code_group);
			GroupFlags::ResetOpen(code_group);
			return;
		}

		// If we have received all original data without loss,
		if (group->original_seen >= block_count) {
			CAT_IF_DUMP(cout << "ALL RECEIVE : " << (int)code_group << endl;)
			// Close the group now
			group->Close(_allocator);
			GroupFlags::SetDone(code_group);
			GroupFlags::ResetOpen(code_group);
			return;
		}
	}

	// Packet that will contain this data
	Packet *p = _allocator.AcquireObject<Packet>();
	p->batch_next = 0;

	// Store ID in id/len field
	p->id = id;

	// If packet ID is from original set,
	if (id < block_count) {
		// Store packet, prepending length.
		// NOTE: We cannot efficiently pad with zeroes yet because we do not
		// necessarily know what the largest packet length is yet.  And anyway
		// we may not need to pad at all if no loss occurs.
		*(u16*)p->data = getLE(data_len);
		memcpy(p->data + 2, data, data_len);

		// Insert it into the original packet list
		group->AddOriginal(p);
	} else {
		// Store recovery packet, which has length included (encoded)
		memcpy(p->data, data, data_len);

		// Insert it into the recovery packet list
		group->AddRecovery(p);
	}

	// Increment total seen count
	group->total_seen++;

	// If recovery is now possible for this group,
	if (group->CanRecover()) {
		wirehair::Result r;

		// The block size will be the largest data chunk we have
		const int block_size = group->largest_len;

		CAT_IF_DUMP(cout << "CAN RECOVER : " << (int)code_group << " : " << id << " < " << block_count << endl;)

		// If we are decoding this group for the first time,
		if (!_decoding || _decoding_group != code_group) {
			// Initialize the decoder
			r = _decoder.InitializeDecoder(block_count * block_size, block_size);

			// We should always initialize correctly
			CAT_ENFORCE(!r && _decoder.BlockCount() == block_count);

			// Decoding process has started
			_decoding = true;
			_decoding_group = code_group;

			// Add original packets
			for (Packet *op = group->head; op; op = (Packet*)op->batch_next) {
				// We need to pad it out to the block size with zeroes.
				// Get length of original packet
				u16 op_len = getLE(*(u16*)op->data);

				// Clear everything after length + original data with zeroes
				CAT_CLR(op->data + 2 + op_len, block_size - (op_len + 2));

				// Feed decoder with data
				r = _decoder.DecodeFeed(op->id, op->data);

				// We should not succeed at decoding at this point
				CAT_ENFORCE(r);
			}

			// Add recovery packets
			for (Packet *op = group->recovery_head; op; op = (Packet*)op->batch_next) {
				// Feed decoder with data
				r = _decoder.DecodeFeed(op->id, op->data);

				// If decoding was successful,
				if (!r) {
					// Recover missing packets
					RecoverGroup(group);
					group->Close(_allocator);
					CAT_IF_DUMP(cout << "GROUP RECOVERED IN ONE : " << (int)code_group << endl;)
					GroupFlags::SetDone(code_group);
					GroupFlags::ResetOpen(code_group);
					_decoding = false;
					break;
				}
			}
		} else {
			// Adding another packet to an existing decoder session:

			// If packet is original,
			if (id < block_count) {
				// Clear everything after length + original data with zeroes
				CAT_CLR(p->data + 2 + data_len, block_size - (data_len + 2));
			}

			// Attempt recovery
			r = _decoder.DecodeFeed(id, p->data);

			// If decoding was successful,
			if (!r) {
				// Recover missing packets
				RecoverGroup(group);
				group->Close(_allocator);
				CAT_IF_DUMP(cout << "GROUP RECOVERED WITH EXTRA : " << (int)code_group << endl;)
				GroupFlags::SetDone(code_group);
				GroupFlags::ResetOpen(code_group);
				_decoding = false;
			}
		}
	} // end if group can recover

	// Clear opposite in number space
	GroupFlags::ClearOpposite(code_group);
}

// Send collected statistics
void Shorthair::SendPong(int code_group) {
	_stats.Calculate();

	u8 pkt[PONG_SIZE + calico::Calico::OVERHEAD];

	// Write packet
	pkt[0] = (u8)code_group | 0x80;
	pkt[1] = PONG_TYPE;
	*(u32*)(pkt + 2) = getLE(_stats.GetSeen());
	*(u32*)(pkt + 2 + 4) = getLE(_stats.GetTotal());

	// Encrypt pong
	int len = _cipher.Encrypt(pkt, PONG_SIZE, pkt, sizeof(pkt));

	CAT_DEBUG_ENFORCE(len == sizeof(pkt));

	// Send it
	_settings.interface->SendData(pkt, len);
}

void Shorthair::OnGroupTimeout(const u8 group) {
	CAT_IF_DUMP(cout << " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ !!!!!!!!!!!!!!!!!!!!!!!!!!! TIMEOUT " << (int)group << endl;)
	_groups[group].Close(_allocator);
}


//// Shorthair: Interface

// On startup:
bool Shorthair::Initialize(const u8 key[SKEY_BYTES], const Settings &settings) {
	Finalize();

	_clock.OnInitialize();

	_settings = settings;

	if (_cipher.Initialize(key, "SHORTHAIR", _settings.initiator ? calico::INITIATOR : calico::RESPONDER)) {
		return false;
	}

	CAT_ENFORCE(_settings.max_data_size <= MAX_CHUNK_SIZE);

	const int buffer_size = SHORTHAIR_OVERHEAD + _settings.max_data_size;

	// Allocate recovery packet workspace
	_packet_buffer.resize(buffer_size);

	// Initialize packet storage buffer allocator
	_allocator.Initialize(sizeof(Packet) - 1 + buffer_size);

	_encoder.Initialize(&_allocator);

	_delay.Initialize(_settings.min_delay, _settings.max_delay);
	_loss.Initialize(_settings.min_loss, _settings.max_loss);

	_redundant_count = 0;
	_redundant_sent = 0;

	_last_swap_time = 0;
	_code_group = 0;

	_last_group = 0;
	_decoding = false;

	_stats.Initialize();

	// Clear group data
	CAT_OBJCLR(_groups);

	CAT_OBJCLR(_group_stamps);

	GroupFlags::Clear();

	CalculateInterval();

	_initialized = true;

	return true;
}

// Cleanup
void Shorthair::Finalize() {
	if (_initialized) {
		_encoder.Finalize();

		_clock.OnFinalize();

		_initialized = false;
	}
}

// Send a new packet
void Shorthair::Send(const void *data, int len) {
	CAT_ENFORCE(len <= _settings.max_data_size);

	Packet *p = _encoder.Queue(len);

	u8 *buffer = p->data;

	const u8 packet_group = _code_group + 1;

	// Add next code group (this is part of the code group after the next swap)
	buffer[0] = packet_group & 0x7f;

	u16 block_count = _encoder.GetCurrentCount();

	// On first packet of a group,
	if (block_count == 1) {
		// Tag this new group with the start time
		_group_stamps[packet_group] = _clock.msec();
	}

	// Add check symbol number
	*(u16*)(buffer + 1) = getLE16(block_count - 1);

	// For original data send the current block count, which will
	// always be one ahead of the block ID.
	// NOTE: This allows the decoder to know when it has received
	// all the packets in a code group for the zero-loss case.
	*(u16*)(buffer + 1 + 2) = getLE(block_count);

	// Copy input data into place
	memcpy(buffer + PROTOCOL_OVERHEAD, data, len);

	// Encrypt
	int bytes = _cipher.Encrypt(buffer, PROTOCOL_OVERHEAD + len, _packet_buffer.get(), _packet_buffer.size());

	// Transmit
	_settings.interface->SendData(_packet_buffer.get(), bytes);
}

// Send an OOB packet, first byte is type code
void Shorthair::SendOOB(const u8 *data, int len) {
	CAT_ENFORCE(len > 0);
	CAT_ENFORCE(data[0] != PONG_TYPE);
	CAT_ENFORCE(1 + len <= _packet_buffer.size())

	u8 *buffer = _packet_buffer.get();

	// Mark OOB
	buffer[0] = 0x80;

	// Copy input data into place
	memcpy(buffer + 1, data, len);

	// Encrypt
	int bytes = _cipher.Encrypt(buffer, 1 + len, buffer, _packet_buffer.size());

	// Transmit
	_settings.interface->SendData(buffer, bytes);
}

// Called once per tick, about 10-20 ms
void Shorthair::Tick() {
	const u32 ms = _clock.msec();

	const int recovery_time = ms - _last_swap_time;
	int expected_sent = _redundant_count;

	// If not swapping the encoder this tick,
	if (recovery_time < _swap_interval) {
		int elapsed = ((_redundant_count + 1) * recovery_time) / _swap_interval;

		// Pick min(_redundant_count, elapsed)
		if (expected_sent > elapsed) {
			expected_sent = elapsed;
		}
	}

	// Calculate number of redundant symbols to send right now
	const int send_count = expected_sent - _redundant_sent;

	// If there are any new packets to send,
	if (send_count > 0) {
		// For each check packet to send,
		for (int ii = 0; ii < send_count; ++ii) {
			if (!SendCheckSymbol()) {
				break;
			}

			++_redundant_sent;
		}
	}

	// If it is time to swap the encoder,
	if (recovery_time >= _swap_interval) {
		_last_swap_time = ms;

		// Packet count
		const int N = _encoder.GetCurrentCount();

		// Calculate number of redundant packets to send this time
		_redundant_count = CalculateRedundancy(_loss.Get(), N, _settings.target_loss);
		_redundant_sent = 0;

		// Select next code group
		_code_group++;

		// NOTE: These packets will be spread out over the swap interval

		// Start encoding queued data in another thread
		_encoder.EncodeQueued();

		CAT_IF_DUMP(cout << "New code group: N = " << N << " R = " << _redundant_count << " loss=" << _loss.Get() << endl;)
	}
}

// On packet received
void Shorthair::Recv(void *pkt, int len) {
	u8 *buffer = static_cast<u8*>( pkt );

	u64 iv;
	len = _cipher.Decrypt(buffer, len, iv);

	// If a message was decoded,
	if (len >= 2) {
		// Update stats
		_stats.Update((u32)iv);

		// If out of band,
		if (buffer[0] & 0x80) {
			OnOOB(buffer, len);
		} else {
			OnData(buffer, len);
		}
	}
}

