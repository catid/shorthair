#include <iostream>
#include <cmath>
#include <vector>
using namespace std;

#include "Platform.hpp"
#include "Enforcer.hpp"
#include "BitMath.hpp"
#include "Clock.hpp"
using namespace cat;

Clock m_clock;

/*
 * Top Level: Calculating Redundancy Required
 *
 * Assuming that the code group size is large enough to eat burst losses, then
 * the loss probability distribution is roughly uniform with probability of loss
 * equal to p.
 *
 * Deriving perceived packet loss rate:
 *
 * let:
 *	p = probability of packet loss
 * 	n = original packet count
 * 	r = redunant packet count
 *
 * 	(n, k) = n chooses k, binomial coefficient = n! / ( k! * (n-k)! )
 *
 * p(l) = p^l * (1 - p)^(n+r-l) = probability of losing l packets of n+r
 *
 * Perceived loss q = sum( p(l) * (n+r, l) ; l = r+1..n+r ), which is the
 * probability of losing r+1 or more packets.
 *
 * Note this is a Bernoulli random variable, which makes it amenable to
 * approximation via the CLT.
 */

/*
 * Normal Approximation
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
 *
 * This is a problem since we also want to solve it exactly for all
 * cases.  So when the approximation breaks down, we evaluate the
 * Bernoulli CDF directly (see later section).
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

/*
 * Normal Approximation Approach
 *
 * Try different values of r until target is reached.
 *
 * NOTE: Pr is not used here (see below) since its effects
 * are not particularly important where this approximation
 * is used.
 */

int CalculateApproximate(double p, int n, double Qtarget) {
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

int CalculateApproximateFast(double p, int n, double Qtarget) {
	double q;
	u32 r;

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

	// Add one extra symbol to fix error of approximation
	if (n * p < 10. || n * (1 - p) < 10.) {
		++r;
	}

	CAT_ENFORCE(CalculateApproximate(p, n, Qtarget) == r);

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

int CalculateRedundancy(double p, int n, double Qtarget, bool force_approx = false) {
	int r;

	double t0 = m_clock.usec();
	// If in region where approximation works,
	if ((n * p >= 10. &&
		n * (1 - p) >= 10.) || force_approx) {
		r = CalculateApproximateFast(p, n, Qtarget);
	} else {
		r = CalculateExact(p, n, 0.97, Qtarget);
	}
	double t1 = m_clock.usec();

	cout << "(in " << t1 - t0 << " usec)";

	return r;
}

/*
 * Discussion:
 *
 * The approximation seems to work fairly well even outside of
 * the "safe" region.  It only seems to be off by 1 at most for
 * normal data.
 *
 * The amount of overhead required appears to go up slower than
 * the block count (N).  This means that larger buffer sizes are
 * more efficient with bandwidth than overlapped encoders,
 * on top of being more compressible.
 *
 * Reducing the target error rate by an order of magnitude takes
 * just a small amount of additional redundancy, so targetting
 * very very low error rates may be a good idea.
 */

int main() {
	cout << "Redundancy Calculator" << endl;

	m_clock.OnInitialize();

	double p = 0.6;
	double Qtarget = 0.0001;

	for (int n = 1; n < 64000; ++n) {
		cout << "n = " << n << " r = " << CalculateRedundancy(p, n, Qtarget) << endl;
		cout << "n = " << n << " r = " << CalculateRedundancy(p, n, Qtarget, true) << endl;
	}

	m_clock.OnFinalize();
}

