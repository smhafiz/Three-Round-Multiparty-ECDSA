#include <chrono>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <set>
#include <string>
#include <vector>

#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

// ---------------------------------------------------------------------------
// Timing helpers
// ---------------------------------------------------------------------------

using Clock = std::chrono::high_resolution_clock;
using Seconds = std::chrono::duration<double>;

struct Stats {
    double mean;
    double min;
    double max;
    double stddev;
};

static Stats compute(const std::vector<double>& v) {
    double sum = 0.0, mn = v[0], mx = v[0];
    for (double x : v) {
        sum += x;
        if (x < mn) mn = x;
        if (x > mx) mx = x;
    }
    const double mean = sum / static_cast<double>(v.size());
    double sq = 0.0;
    for (double x : v) sq += (x - mean) * (x - mean);
    return {mean, mn, mx, std::sqrt(sq / static_cast<double>(v.size()))};
}

// ---------------------------------------------------------------------------
// Result per scenario
// ---------------------------------------------------------------------------

struct ScenarioResult {
    const char* level_name;
    size_t n, t;
    Stats setup, dkg, sign, verify;
    trecdsa::BandwidthStats bw;
    bool ok;
};

// ---------------------------------------------------------------------------
// Run one scenario, collect all measurements
// ---------------------------------------------------------------------------

static ScenarioResult run_scenario(trecdsa::SecurityLevel level, const char* level_name,
                                   size_t n, size_t t,
                                   size_t setup_trials, size_t dkg_trials, size_t sign_trials) {
    // 1. GroupParams construction
    std::vector<double> setup_times;
    setup_times.reserve(setup_trials);
    for (size_t i = 0; i < setup_trials; ++i) {
        auto t0 = Clock::now();
        trecdsa::GroupParams p(level, n, t);
        (void)p;
        setup_times.push_back(Seconds(Clock::now() - t0).count());
    }

    // 2. DKG
    trecdsa::GroupParams params(level, n, t);
    std::vector<double> dkg_times;
    dkg_times.reserve(dkg_trials);
    for (size_t i = 0; i < dkg_trials; ++i) {
        trecdsa::Protocol proto(params);
        auto t0 = Clock::now();
        proto.run_dkg();
        dkg_times.push_back(Seconds(Clock::now() - t0).count());
    }

    // 3. Signing — reuse one DKG; vary message and party set each trial
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();

    std::vector<double> sign_times;
    sign_times.reserve(sign_trials);
    bool all_valid = true;
    trecdsa::BandwidthStats bw{};

    for (size_t i = 0; i < sign_trials; ++i) {
        std::set<size_t> party_set = trecdsa::select_parties(n, t);
        std::vector<unsigned char> msg;
        trecdsa::randomize_message(msg);

        auto t0 = Clock::now();
        std::vector<trecdsa::Signature> sigs = protocol.run(party_set, msg);
        sign_times.push_back(Seconds(Clock::now() - t0).count());

        all_valid &= protocol.verify(sigs, msg);
        bw = protocol.last_bandwidth();
    }

    // 4. Verify — isolated from signing
    std::set<size_t> vset = trecdsa::select_parties(n, t);
    std::vector<unsigned char> vmsg;
    trecdsa::randomize_message(vmsg);
    (void) protocol.run(vset, vmsg);

    std::vector<double> verify_times;
    verify_times.reserve(sign_trials);
    std::vector<trecdsa::Signature> vsigs = protocol.run(vset, vmsg);
    for (size_t i = 0; i < sign_trials; ++i) {
        auto t0 = Clock::now();
        (void) protocol.verify(vsigs, vmsg);
        verify_times.push_back(Seconds(Clock::now() - t0).count());
    }

    return {level_name, n, t,
            compute(setup_times), compute(dkg_times),
            compute(sign_times), compute(verify_times),
            bw, all_valid};
}

// ---------------------------------------------------------------------------
// Print helpers
// ---------------------------------------------------------------------------

static void print_sep(char c = '-', int w = 115) {
    std::cout << std::string(static_cast<size_t>(w), c) << '\n';
}

static void print_timing_table(const std::vector<ScenarioResult>& results) {
    print_sep('=');
    std::cout << std::left
              << std::setw(8)  << "SecLvl"
              << std::setw(5)  << "n"
              << std::setw(5)  << "t"
              << std::right
              << std::setw(14) << "Setup (ms)"
              << std::setw(12) << "DKG (ms)"
              << std::setw(14) << "Sign (ms)"
              << std::setw(10) << "±σ (ms)"
              << std::setw(10) << "Min (ms)"
              << std::setw(10) << "Max (ms)"
              << std::setw(13) << "Verify (ms)"
              << std::setw(14) << "Throughput"
              << '\n';
    print_sep();
    const double ms = 1000.0;
    for (const auto& r : results) {
        std::cout << std::left  << std::fixed << std::setprecision(1)
                  << std::setw(8)  << r.level_name
                  << std::setw(5)  << r.n
                  << std::setw(5)  << r.t
                  << std::right
                  << std::setw(14) << r.setup.mean   * ms
                  << std::setw(12) << r.dkg.mean     * ms
                  << std::setw(14) << r.sign.mean    * ms
                  << std::setw(10) << r.sign.stddev  * ms
                  << std::setw(10) << r.sign.min     * ms
                  << std::setw(10) << r.sign.max     * ms
                  << std::setw(13) << r.verify.mean  * ms
                  << std::setprecision(2)
                  << std::setw(12) << (1.0 / r.sign.mean) << " sig/s"
                  << '\n';
    }
    print_sep('=');
}

static void print_bandwidth_table(const std::vector<ScenarioResult>& results) {
    print_sep('=');
    std::cout << std::left
              << std::setw(8)  << "SecLvl"
              << std::setw(5)  << "n"
              << std::setw(5)  << "t"
              << std::setw(9)  << "signers"
              << std::right
              << std::setw(13) << "Round1 (KB)"
              << std::setw(13) << "Round2 (KB)"
              << std::setw(13) << "Round3 (KB)"
              << std::setw(13) << "Total (KB)"
              << std::setw(16) << "Per-party (KB)"
              << '\n';
    print_sep();
    const double kb = 1024.0;
    for (const auto& r : results) {
        const size_t signers = r.t + 1;
        std::cout << std::left  << std::fixed << std::setprecision(1)
                  << std::setw(8) << r.level_name
                  << std::setw(5) << r.n
                  << std::setw(5) << r.t
                  << std::setw(9) << signers
                  << std::right
                  << std::setw(13) << static_cast<double>(r.bw.round1_bytes) / kb
                  << std::setw(13) << static_cast<double>(r.bw.round2_bytes) / kb
                  << std::setw(13) << static_cast<double>(r.bw.round3_bytes) / kb
                  << std::setw(13) << static_cast<double>(r.bw.total_bytes)  / kb
                  << std::setw(16) << static_cast<double>(r.bw.total_bytes)  / kb
                                      / static_cast<double>(signers)
                  << '\n';
    }
    print_sep('=');
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

int main() {
    constexpr size_t SETUP_TRIALS = 2;
    constexpr size_t DKG_TRIALS   = 2;
    constexpr size_t SIGN_TRIALS  = 8;

    std::cout << "\nThree-Round Multiparty ECDSA — Benchmark\n";
    std::cout << "Setup trials: " << SETUP_TRIALS
              << "  |  DKG trials: " << DKG_TRIALS
              << "  |  Sign trials: " << SIGN_TRIALS << "\n";

    // --- Security level sweep (n=5, t=2) ---------------------------------
    std::cout << "\n--- Security level sweep  (n=5, t=2, t+1=3 signers) ---\n";
    std::vector<ScenarioResult> sec_sweep;
    sec_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_112, "112", 5, 2, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));
    sec_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_128, "128", 5, 2, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));
    // _192 and _256 take several minutes per signing; uncomment to measure:
    // sec_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_192, "192", 5, 2, 1, 1, 3));
    // sec_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_256, "256", 5, 2, 1, 1, 3));

    std::cout << "\nTiming:\n";
    print_timing_table(sec_sweep);
    std::cout << "\nBandwidth (total across all t+1 signers, per signing):\n";
    print_bandwidth_table(sec_sweep);

    // --- Party / threshold sweep (128-bit) --------------------------------
    std::cout << "\n--- Party / threshold sweep  (128-bit security) ---\n";
    std::vector<ScenarioResult> pt_sweep;
    pt_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_128, "128",  3, 1, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));
    pt_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_128, "128",  3, 2, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));
    pt_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_128, "128",  5, 2, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));
    pt_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_128, "128",  5, 4, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));
    pt_sweep.push_back(run_scenario(trecdsa::SecurityLevel::_128, "128", 10, 5, SETUP_TRIALS, DKG_TRIALS, SIGN_TRIALS));

    std::cout << "\nTiming:\n";
    print_timing_table(pt_sweep);
    std::cout << "\nBandwidth (total across all t+1 signers, per signing):\n";
    print_bandwidth_table(pt_sweep);

    bool all_ok = true;
    for (const auto& r : sec_sweep) all_ok &= r.ok;
    for (const auto& r : pt_sweep)  all_ok &= r.ok;

    std::cout << "\nAll signatures verified: " << (all_ok ? "YES" : "NO -- CORRECTNESS FAILURE") << "\n";
    std::cout << "\nNotes:\n"
              << "  Setup      : GroupParams construction (class group setup, one-time per config)\n"
              << "  DKG        : Distributed key generation (one-time per session)\n"
              << "  Sign       : Full 3-round signing for t+1 parties (mean over " << SIGN_TRIALS << " trials)\n"
              << "  Verify     : Standard ECDSA check (~free, negligible vs. signing)\n"
              << "  Throughput : Signings/sec  =  1 / Sign_mean\n"
              << "  Round1 BW  : enc(φ_i) + commitment + ZKAoK proof  [ZKAoK is an upper-bound estimate]\n"
              << "  Round2 BW  : 2x CL scalar-mult + EC point + opening + 3x ZK proofs  [exact]\n"
              << "  Round3 BW  : 2x QFI partial-dec shares + 2x partial-dec ZK proofs  [exact]\n"
              << "  Per-party  : Total / (t+1) — bytes each signer sends across all 3 rounds\n";

    return all_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
