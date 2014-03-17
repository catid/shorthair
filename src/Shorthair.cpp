/*
	Copyright (c) 2013-2014 Christopher A. Taylor.  All rights reserved.

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
#include "Mutex.hpp"
using namespace cat;
using namespace shorthair;

//#define CAT_DUMP_SHORTHAIR

#if !defined(CAT_DUMP_SHORTHAIR)
#define LOG(fmt, ...)
#else
#ifdef CAT_OS_ANDROID
#include <android/log.h>
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_INFO, "shorthair", fmt, __VA_ARGS__);
#else
#include <cstdio>
#define LOG(fmt, ...) printf("{shorthair}" fmt "\r\n", __VA_ARGS__);
#endif
#endif

#include <cmath>
#include <vector>
using namespace std;

static Mutex m_mutex;


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
	_real_loss = 0;
	_clamped_loss = min_loss;
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
		float loss = (float)((count - seen) / (double)count);
		_real_loss = loss;

		// Clamp value
		if (loss < _min_loss) {
			loss = _min_loss;
		} else if (loss > _max_loss) {
			loss = _max_loss;
		}

		_clamped_loss = loss;
	} else {
		_real_loss = 0;
		_clamped_loss = _min_loss;
	}
}


//// CodeGroup

void CodeGroup::Open(u32 ms) {
	open = true;
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


//// Encoder

void Encoder::Initialize(ReuseAllocator *allocator) {
	Finalize();

	_allocator = allocator;
	_head = 0;
	_tail = 0;
	_original_count = 0;
	_k = 0;
	_m = 0;
	_next_recovery_block = 0;
	_block_bytes = 0;
	_largest = 0;

	_initialized = true;
}

void Encoder::Finalize() {
	if (_initialized) {
		FreeGarbage();
	}
}

void Encoder::Queue(Packet *p) {
	int len = p->len;

	CAT_ENFORCE(len > 0);

	AutoMutex guard(m_mutex);

	// If this new packet is larger than the previous ones,
	if (_largest < len) {
		// Remember the largest size for when we start emitting check symbols
		_largest = len;
	}

	// Insert at end of list
	if (_tail) {
		_tail->batch_next = p;
	} else {
		_head = p;
	}
	_tail = p;

	_original_count++;
}

void Encoder::EncodeQueued(int m) {
	AutoMutex guard(m_mutex);

	LOG("** Started encoding m=%d and k=%d largest bytes=%d", m, _original_count, _largest);

	// Abort if input is invalid
	CAT_DEBUG_ENFORCE(m > 0);
	if (m < 1) {
		_m = 0;
		return;
	}

	const int k = _original_count;
	CAT_DEBUG_ENFORCE(k < 256);
	if (k <= 0 || k >= 256) {
		_m = 0;
		return;
	}

	// Truncate recovery count if needed (always possible)
	if (k + m > 256) {
		m = 256 - k;
	}

	// Optimization: If k = 1,
	if (k == 1) {
		int len = _largest;

		LOG("Encoding queued k = 1 special case len=%d", _largest);
		CAT_DEBUG_ENFORCE(_head != 0);
		CAT_DEBUG_ENFORCE(_head->len == len);

		_k = 1; // Treated specially during generation
		_block_bytes = len;

		_buffer.resize(len);

		// Correct for packet that has stats attached
		u8 *pkt = _head->data;
		if (pkt[2] == 0x81) {
			pkt += 9;
		}

		memcpy(_buffer.get(), pkt + ORIGINAL_OVERHEAD, len);
	} else {
		CAT_DEBUG_ENFORCE(_largest > 0);

		// Calculate block size
		int block_size = 2 + _largest;

		// Round up to the nearest multiple of 8
		block_size = (u32)(block_size + 7) & ~(u32)7;

		CAT_DEBUG_ENFORCE(block_size % 8 == 0);

		const u8 *data_ptrs[256];
		int index = 0;

		// Massage data for use in codec
		for (Packet *p = _head; index < k && p; p = (Packet*)p->batch_next, ++index) {
			u8 *pkt = p->data + ORIGINAL_OVERHEAD - 2;
			u16 len = p->len;

			// Correct for packet that has stats attached
			if (pkt[-1] == 0x81) {
				pkt += 9;
			}

			// Setup data pointer
			data_ptrs[index] = pkt;

			// Prefix data by its length
			*(u16*)pkt = getLE16(len);

			// Pad message up to the block size with zeroes
			CAT_CLR(pkt + len + 2, block_size - (len + 2));
		}

		CAT_DEBUG_ENFORCE(index == k);

		// Set up encode buffer to receive the recovery blocks
		_buffer.resize(m * block_size);

		// Produce recovery blocks
		CAT_ENFORCE(0 == cauchy_256_encode(k, m, data_ptrs, _buffer.get(), block_size));

		// Start from from of encode buffer
		_next_recovery_block = 0;

		// Store block size
		_block_bytes = block_size;

		// Store parameters
		_m = m;
		_k = k;
	}

	// Reset encoder queuing:

	FreeGarbage();

	_original_count = 0;
	_largest = 0;
}

// Returns 0 if recovery blocks cannot be sent yet
int Encoder::GenerateRecoveryBlock(u8 *pkt) {
	const int block_bytes = _block_bytes;

	//CAT_IF_DUMP(cout << "<< Generated recovery block id = " << _next_recovery_block << " block_bytes=" << _block_bytes << endl);

	// Optimization: If k = 1,
	if (_k == 1) {
		LOG("Writing k = 1 special form len=%d", block_bytes);

		// Write special form
		pkt[0] = 1;
		pkt[1] = 0;
		memcpy(pkt + 2, _buffer.get(), block_bytes);

		return 2 + block_bytes;
	}

	// If ran out of recovery data to send,
	if (_next_recovery_block >= _m) {
		return 0;
	}

	const int index = _next_recovery_block++;

	// Write header
	pkt[0] = (u8)(_k + index);
	pkt[1] = (u8)(_k - 1);
	pkt[2] = (u8)(_m - 1);

	const u8 *src = _buffer.get() + block_bytes * index;

	// Write data
	memcpy(pkt + 3, src, block_bytes);

	// Return bytes written
	return 3 + block_bytes;
}


//// Shorthair : Encoder

// Send a check symbol
bool Shorthair::SendCheckSymbol() {
	u8 *pkt = _sym_buffer.get();
	int len = _encoder.GenerateRecoveryBlock(pkt + 3);

	// If no data to send,
	if (len <= 0) {
		return false;
	}

	// Insert next sequence number
	*(u16*)pkt = getLE16(_out_seq++);

	// Prepend the code group
	pkt[2] = _code_group & 0x7f;

	_settings.interface->SendData(pkt, len + 3);

	return true;
}

void Shorthair::UpdateLoss(u32 seen, u32 count) {
	CAT_DEBUG_ENFORCE(seen <= count);
	if (seen > count) {
		// Ignore invalid data
		return;
	}

	if (count > 0) {
		_loss.Insert(seen, count);
		_loss.Calculate();
	}
}

void Shorthair::OnOOB(u8 flags, u8 *pkt, int len) {
	// If it contains a pong message,
	if (flags & 1) {
		// If truncated,
		CAT_DEBUG_ENFORCE(len >= 8);
		if (len < 8) {
			return;
		}

		// Update stats
		u32 seen = getLE(*(u32*)pkt);
		u32 count = getLE(*(u32*)(pkt + 4));
		UpdateLoss(seen, count);

		LOG("++ Updating loss stats from OOB header: %d / %d", seen, count);

		pkt += 8;
		len -= 8;

		// If out of band,
		if (pkt[0] & 0x80) {
			OnOOB(0, pkt + 1, len - 1);
			// NOTE: Does not allow attacker to cause more recursion
		} else {
			OnData(pkt, len);
		}
	} else {
		LOG("Delivering OOB data of length %d and type = %d", len, (int)pkt[0]);

		// Pass OOB data to the interface
		_settings.interface->OnOOB(pkt, len);
	}
}


//// Shorthair : Decoder

void Shorthair::RecoverGroup(CodeGroup *group) {
	// The block size will be the largest data chunk we have
	const int block_size = group->largest_len;
	const int k = group->block_count;

	int index = 0;
	Block blocks[256];

	// Add original packets
	for (Packet *op = group->head; op; op = (Packet*)op->batch_next) {
		// We need to pad it out to the block size with zeroes.
		// Get length of original packet
		u16 op_len = getLE(*(u16*)op->data);

		// Clear everything after length + original data with zeroes
		CAT_CLR(op->data + 2 + op_len, block_size - (op_len + 2));

		// Fill in block for codec
		blocks[index].data = op->data;
		blocks[index].row = (u8)op->id;

		++index;
	}

	CAT_DEBUG_ENFORCE(index == group->original_seen);

	// Add recovery packets up to k
	for (Packet *rp = group->recovery_head; index < k && rp; rp = (Packet*)rp->batch_next) {
		// Fill in block for codec
		blocks[index].data = rp->data;
		blocks[index].row = (u8)rp->id;

		++index;
	}

	const int m = group->recovery_count;

	CAT_DEBUG_ENFORCE(k + m <= 256);
	CAT_DEBUG_ENFORCE(index == k);

	LOG("CRS decode with k=%d, m=%d block_size=%d, #originals=%d", k, m, block_size, group->original_seen);

	// Decode the data
	CAT_ENFORCE(0 == cauchy_256_decode(k, m, blocks, block_size));

	// For each recovery packet,
	for (int ii = group->original_seen; ii < k; ++ii) {
		// The data was decoded in-place
		u8 *src = blocks[ii].data;
		int len = getLE(*(u16*)src);

		CAT_DEBUG_ENFORCE(len <= block_size - 2);

		if (len <= block_size - 2) {
			_settings.interface->OnPacket(src + 2, len);
		}
	}
}

// On receiving a data packet
void Shorthair::OnData(u8 *pkt, int len) {
	if (len <= PROTOCOL_OVERHEAD) {
		return;
	}

	// Read packet data
	int code_group = (u32)ReconstructCounter<7, u8>(_last_group, pkt[0]);
	CodeGroup *group = &_groups[code_group];
	_last_group = code_group;

	// If this group is already done,
	if (GroupFlags::IsDone(code_group)) {
		// Ignore more data received for this group
		return;
	}

	// If group is not open yet,
	if (!group->open) {
		openGroup(group, code_group);

		LOG("~~ Opening group %d", (int)code_group);
	}

	int id = (u32)pkt[1];
	int block_count = (u32)pkt[2] + 1;

	u8 *data = pkt + 3;
	int data_len = len - 3;

	LOG("~~ ACTUAL GOT id %d bc %d cg %d", id, block_count, (int)code_group);

	// If block count is not the largest seen for this group,
	if (block_count < group->block_count) {
		// Use the latest
		block_count = group->block_count;
	} else {
		// Update largest block count seen for group
		group->block_count = block_count;
	}

	// If packet contains original data,
	if (id < block_count) {
		LOG("~~ GOT id %d bc %d cg %d", id, block_count, (int)code_group);
		// Process it immediately
		_settings.interface->OnPacket(data, data_len);

		// Increment original seen count
		group->original_seen++;

		// Packet that will contain this data
		Packet *p = _allocator.AcquireObject<Packet>();
		p->batch_next = 0;

		// Store ID in id/len field
		p->id = (u16)id;

		// Store packet, prepending length.
		// NOTE: We cannot efficiently pad with zeroes yet because we do not
		// necessarily know what the largest packet length is yet.  And anyway
		// we may not need to pad at all if no loss occurs.
		*(u16*)p->data = getLE16((u16)data_len);
		memcpy(p->data + 2, data, data_len);

		// Insert it into the original packet list
		group->AddOriginal(p);
	} else {
		if (group->original_seen >= block_count) {
			LOG("~~ Closing group %d: Just noticed all originals are received", (int)code_group);

			// See above: Original data gets processed immediately
			closeGroup(group, code_group);
			return;
		} else if (block_count == 1) {
			LOG("~~ Closing group %d: Special case k = 1 and a redundant packet won", (int)code_group);

			CAT_DEBUG_ENFORCE(group->original_seen == 0);

			_settings.interface->OnPacket(data, data_len);

			closeGroup(group, code_group);
			return;
		}

		// If ID is the largest seen so far,
		if (id > group->largest_id) {
			// Update largest seen ID for decoding ID in next packet
			group->largest_id = id;
		}

		// Pull in codec parameters
		group->largest_len = data_len - 1;
		group->recovery_count = (u32)pkt[3] + 1;

		// Packet that will contain this data
		Packet *p = _allocator.AcquireObject<Packet>();
		p->batch_next = 0;

		// Store ID in id/len field
		p->id = (u16)id;

		// Store recovery packet, which has length included (encoded)
		memcpy(p->data, data + 1, data_len - 1);

		// Insert it into the recovery packet list
		group->AddRecovery(p);
	}

	// Increment total seen count
	group->total_seen++;

	// If recovery is now possible for this group,
	if (group->CanRecover()) {
		LOG("~~ Closing group %d: Recovered!", (int)code_group);

		RecoverGroup(group);

		closeGroup(group, code_group);
	} // end if group can recover

	// Clear opposite in number space
	GroupFlags::ClearOpposite(code_group);
}

void Shorthair::OnGroupTimeout(const u8 group) {
	LOG("~~ Closing group %d: Timeout", (int)group);
	_groups[group].Close(_allocator);
}


//// Shorthair: Interface

// On startup:
bool Shorthair::Initialize(const Settings &settings) {
	Finalize();

	cauchy_256_init();

	_clock.OnInitialize();

	_settings = settings;

	CAT_ENFORCE(_settings.max_data_size <= MAX_CHUNK_SIZE);

	const int buffer_size = SHORTHAIR_OVERHEAD + _settings.max_data_size;

	// Allocate recovery packet workspace
	_sym_buffer.resize(buffer_size);
	_oob_buffer.resize(buffer_size);

	// Initialize packet storage buffer allocator
	_allocator.Initialize(sizeof(Packet) - 1 + buffer_size);

	_encoder.Initialize(&_allocator);

	_loss.Initialize(SHORTHAIR_MIN_LOSS_ESTIMATE, SHORTHAIR_MAX_LOSS_ESTIMATE);

	_redundant_count = 0;
	_redundant_sent = 0;

	_last_swap_time = 0;
	_code_group = 0;

	_last_group = 0;

	_out_seq = 0;
	_send_stats = false;
	_last_stats = 0;

	_stats.Initialize();

	// Clear group data
	CAT_OBJCLR(_groups);

	GroupFlags::Clear();

	_initialized = true;

	return true;
}

// Cleanup
void Shorthair::Finalize() {
	if (_initialized) {
		// NOTE: The allocator object will free allocated memory in its dtor

		_encoder.Finalize();

		_clock.OnFinalize();

		_initialized = false;
	}
}

// Send original data
void Shorthair::Send(const void *data, int len) {
	CAT_ENFORCE(len <= _settings.max_data_size);

	// Allocate sent packet buffer
	Packet *p = _allocator.AcquireObject<Packet>();
	p->batch_next = 0;
	p->len = len;

	u8 *pkt = p->data;
	int pkt_len = len + ORIGINAL_OVERHEAD;

	// Insert sequence number at the front
	*(u16*)pkt = getLE16(_out_seq++);

	// If time to send stats,
	if (_send_stats) {
		_send_stats = false;

		// Attach stats to the front
		pkt[2] = 0x81;
		*(u32*)(pkt + 3) = getLE32(_stats.GetSeen());
		*(u32*)(pkt + 7) = getLE32(_stats.GetTotal());

		pkt += 11;
		pkt_len += 9;
	} else {
		pkt += 2;
	}

	// Add next code group (this is part of the code group after the next swap)
	const u8 code_group = _code_group + 1;
	pkt[0] = code_group & 0x7f;

	const u8 id = (u8)_encoder.GetCurrentCount();

	// Add check symbol number
	pkt[1] = id; // id of packet

	// For original data send the current block count, which will
	// always be one ahead of the block ID.
	// NOTE: This allows the decoder to know when it has received
	// all the packets in a code group for the zero-loss case.
	pkt[2] = id; // k - 1

	// Copy input data into place
	memcpy(pkt + 3, data, len);

	// Transmit
	_settings.interface->SendData(p->data, pkt_len);

	// Queue after sending to avoid lock latency
	_encoder.Queue(p);
}

// Send an OOB packet, first byte is type code
void Shorthair::SendOOB(const u8 *data, int len) {
	CAT_ENFORCE(len > 0);
	CAT_ENFORCE(1 + len <= _oob_buffer.size());

	u8 *pkt = _oob_buffer.get();
	u8 *pkt_front = pkt;
	int pkt_len = len + 3;

	// Insert sequence number at the front
	*(u16*)pkt = getLE16(_out_seq++);

	// If time to send stats,
	if (_send_stats) {
		_send_stats = false;

		// Attach stats to the front
		pkt[2] = 0x81;
		*(u32*)(pkt + 3) = getLE32(_stats.GetSeen());
		*(u32*)(pkt + 7) = getLE32(_stats.GetTotal());

		pkt += 11;
		pkt_len += 9;
	} else {
		pkt += 2;
	}

	// Mark OOB
	pkt[0] = 0x80;

	// Copy input data into place
	memcpy(pkt + 1, data, len);

	// Transmit
	_settings.interface->SendData(pkt_front, pkt_len);
}

// Called once per tick, about 10-20 ms
void Shorthair::Tick() {
	const u32 now = _clock.msec();

	const int recovery_time = now - _last_swap_time;
	int expected_sent = _redundant_count;
	u32 max_delay = _settings.max_delay;

	// If it is time to send stats again,
	if ((u32)(now - _last_stats) > (u32)STAT_TRANSMIT_INTERVAL) {
		_last_stats = now;

		// If stats still not sent from last time,
		if (_send_stats) {
			u8 pkt[11];

			// Insert sequence number at the front
			*(u16*)pkt = getLE16(_out_seq++);

			pkt[2] = 0x81;
			*(u32*)(pkt + 3) = getLE32(_stats.GetSeen());
			*(u32*)(pkt + 7) = getLE32(_stats.GetTotal());

			// Transmit
			_settings.interface->SendData(pkt, 11);
		}

		// Calculate new stats
		_stats.Calculate();

		LOG("******** COLLECTED STATS = %d %d", _stats.GetSeen(), _stats.GetTotal());

		_send_stats = true;
	}

	// If not swapping the encoder this tick,
	if ((u32)recovery_time < max_delay) {
		int elapsed = ((_redundant_count + 1) * recovery_time) / max_delay;

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
	if ((u32)recovery_time >= max_delay) {
		_last_swap_time = now;

		// Packet count
		const int N = _encoder.GetCurrentCount();

		if (N > 0) {
			// Calculate number of redundant packets to send this time
			int R = CalculateRedundancy(_loss.GetClamped(), N, _settings.target_loss);

			/*
			 * The redundant count should not be larger than the original
			 * number of data packets, unless the amount of data is small.
			 */

			// If there are a lot of recovery packets,
			if (R > N) {
				// If there are also a lot of data packets,
				if (N > 3) {
					// Do not do more than double the bandwidth
					R = N;
				} else {
					// For smaller sets of data it is okay to multiply the data to meet a goal
					R = 3;
				}
			}

			// NOTE: These packets will be spread out over the swap interval
			_redundant_count = R;
			_redundant_sent = 0;

			// Select next code group
			_code_group++;

			LOG("New code group %d: N = %d R = %d loss=%f[acted on %f]", (int)_code_group, N, R, _loss.GetReal(), _loss.GetClamped());

			// Encode queued data now
			_encoder.EncodeQueued(R);
		}
	}
}

// On packet received
void Shorthair::Recv(void *vpkt, int len) {
	u8 *pkt = static_cast<u8*>( vpkt );

	// If the header is not truncated,
	CAT_DEBUG_ENFORCE(len >= 3);
	if (len >= 3) {
		// Read 16-bit sequence number from the front
		u16 seq = getLE16(*(u16*)pkt);

		// If out of band,
		if (pkt[2] & 0x80) {
			OnOOB(pkt[2], pkt + 3, len - 3);
		} else {
			OnData(pkt + 2, len - 2);
		}

		// Update stats
		_stats.Update(seq);
	}
}

