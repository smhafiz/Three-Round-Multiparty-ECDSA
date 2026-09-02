// trecdsa-eval runs one (security level, n, t) scenario and writes a single
// schema-conformant JSON result file for the tss-eval-harness.
//
// It is the tr-ecdsa counterpart to that harness's Go adapter for tss-lib
// (adapters/tss-lib/cmd/tecdsa-eval). Unlike tss-lib, which needed a separate
// adapter module, this app lives in the implementation repo and speaks the
// harness schema natively -- see schema/result_schema.json in tss-eval-harness
// for the output shape and schema/SCHEMA.md for the field semantics and the
// numbered non-comparability caveats referenced in the comments below.
//
// Measurement conventions follow apps/bench/main.cpp so the two agree:
// population standard deviation, signing timed over repeated trials with a
// fresh message and party set each time, and verification timed separately.

#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include <trecdsa/Protocol.h>
#include <trecdsa/Utils.h>

namespace {

using Clock = std::chrono::high_resolution_clock;
using Seconds = std::chrono::duration<double>;

// ---------------------------------------------------------------------------
// Statistics
// ---------------------------------------------------------------------------

struct Stats {
    double mean = 0.0;
    double min = 0.0;
    double max = 0.0;
    double stddev = 0.0;
};

// Takes seconds, returns milliseconds -- the schema stores milliseconds, and
// doing the conversion once here keeps it out of every call site.
//
// Population standard deviation (divisor N), matching apps/bench: a phase may
// legitimately have a single sample, and reporting 0 for it is honest where a
// sample stddev would divide by zero.
Stats compute_stats(const std::vector<double>& seconds) {
    if (seconds.empty()) {
        return {};
    }
    double sum = 0.0;
    double mn = seconds[0];
    double mx = seconds[0];
    for (const double x : seconds) {
        sum += x;
        if (x < mn) mn = x;
        if (x > mx) mx = x;
    }
    const double n = static_cast<double>(seconds.size());
    const double mean = sum / n;
    double sq = 0.0;
    for (const double x : seconds) {
        sq += (x - mean) * (x - mean);
    }
    constexpr double kMs = 1000.0;
    return {mean * kMs, mn * kMs, mx * kMs, std::sqrt(sq / n) * kMs};
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

struct Options {
    int level = 0;
    size_t n = 0;
    size_t t = 0;
    size_t setup_trials = 2;
    size_t dkg_trials = 2;
    size_t sign_trials = 8;
    std::string out;
    std::string git_commit = "unknown";
};

void usage(const char* argv0) {
    std::cerr << "usage: " << argv0
              << " --level=112|128|192|256 --n=<int> --t=<int>"
                 " [--setup-trials=N] [--dkg-trials=N] [--sign-trials=N]"
                 " [--out=<path>] [--git-commit=<sha>]\n";
}

// Returns the value of `--name=value`, or nullopt if arg is a different flag.
std::optional<std::string> match(const std::string& arg, const std::string& name) {
    const std::string prefix = name + "=";
    if (arg.rfind(prefix, 0) == 0) {
        return arg.substr(prefix.size());
    }
    return std::nullopt;
}

bool parse_size(const std::string& v, size_t& out) {
    try {
        const long long parsed = std::stoll(v);
        if (parsed < 0) return false;
        out = static_cast<size_t>(parsed);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool parse_int(const std::string& v, int& out) {
    try {
        out = std::stoi(v);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool parse_args(int argc, char** argv, Options& opt) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (auto v = match(arg, "--level")) {
            if (!parse_int(*v, opt.level)) return false;
        } else if (auto v2 = match(arg, "--n")) {
            if (!parse_size(*v2, opt.n)) return false;
        } else if (auto v3 = match(arg, "--t")) {
            if (!parse_size(*v3, opt.t)) return false;
        } else if (auto v4 = match(arg, "--setup-trials")) {
            if (!parse_size(*v4, opt.setup_trials)) return false;
        } else if (auto v5 = match(arg, "--dkg-trials")) {
            if (!parse_size(*v5, opt.dkg_trials)) return false;
        } else if (auto v6 = match(arg, "--sign-trials")) {
            if (!parse_size(*v6, opt.sign_trials)) return false;
        } else if (auto v7 = match(arg, "--out")) {
            opt.out = *v7;
        } else if (auto v8 = match(arg, "--git-commit")) {
            opt.git_commit = *v8;
        } else {
            std::cerr << "unknown argument: " << arg << "\n";
            return false;
        }
    }
    return true;
}

std::optional<trecdsa::SecurityLevel> to_level(int level) {
    switch (level) {
        case 112: return trecdsa::SecurityLevel::_112;
        case 128: return trecdsa::SecurityLevel::_128;
        case 192: return trecdsa::SecurityLevel::_192;
        case 256: return trecdsa::SecurityLevel::_256;
        default: return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

struct Measurement {
    Stats setup;
    Stats dkg;
    Stats sign;
    Stats verify;
    trecdsa::BandwidthStats bandwidth{};
    trecdsa::ObjectSizes sizes{};
    bool all_valid = true;
};

Measurement run_scenario(trecdsa::SecurityLevel level, const Options& opt) {
    Measurement m;

    // Setup: GroupParams construction, i.e. class-group parameter generation.
    // This is one-time per configuration and is a different kind of work from
    // tss-lib's per-party Paillier safe-prime search (SCHEMA.md caveat 6).
    std::vector<double> setup_times;
    setup_times.reserve(opt.setup_trials);
    for (size_t i = 0; i < opt.setup_trials; ++i) {
        const auto t0 = Clock::now();
        trecdsa::GroupParams probe(level, opt.n, opt.t);
        (void)probe;
        setup_times.push_back(Seconds(Clock::now() - t0).count());
    }
    m.setup = compute_stats(setup_times);

    trecdsa::GroupParams params(level, opt.n, opt.t);

    // DKG, timed on its own protocol instances so signing state does not
    // perturb it.
    std::vector<double> dkg_times;
    dkg_times.reserve(opt.dkg_trials);
    for (size_t i = 0; i < opt.dkg_trials; ++i) {
        trecdsa::Protocol proto(params);
        const auto t0 = Clock::now();
        proto.run_dkg();
        dkg_times.push_back(Seconds(Clock::now() - t0).count());
    }
    m.dkg = compute_stats(dkg_times);

    // Signing reuses one DKG, with a fresh message and a fresh signer subset
    // per trial.
    trecdsa::Protocol protocol(params);
    protocol.run_dkg();
    m.sizes = protocol.object_sizes();

    std::vector<double> sign_times;
    sign_times.reserve(opt.sign_trials);
    for (size_t i = 0; i < opt.sign_trials; ++i) {
        const std::set<size_t> party_set = trecdsa::select_parties(opt.n, opt.t);
        std::vector<unsigned char> msg;
        trecdsa::randomize_message(msg);

        const auto t0 = Clock::now();
        const std::vector<trecdsa::Signature> sigs = protocol.run(party_set, msg);
        sign_times.push_back(Seconds(Clock::now() - t0).count());

        if (!protocol.verify(sigs, msg)) {
            m.all_valid = false;
        }
        // Bandwidth from the last trial rather than a mean -- message sizes are
        // near-deterministic, so this is a representative figure, not a
        // statistic (SCHEMA.md caveat 9).
        m.bandwidth = protocol.last_bandwidth();
    }
    m.sign = compute_stats(sign_times);

    // Verification timed in isolation over one already-produced signature, so
    // it is never folded into the signing measurement.
    const std::set<size_t> vset = trecdsa::select_parties(opt.n, opt.t);
    std::vector<unsigned char> vmsg;
    trecdsa::randomize_message(vmsg);
    const std::vector<trecdsa::Signature> vsigs = protocol.run(vset, vmsg);

    std::vector<double> verify_times;
    verify_times.reserve(opt.sign_trials);
    for (size_t i = 0; i < opt.sign_trials; ++i) {
        const auto t0 = Clock::now();
        (void)protocol.verify(vsigs, vmsg);
        verify_times.push_back(Seconds(Clock::now() - t0).count());
    }
    m.verify = compute_stats(verify_times);

    return m;
}

// ---------------------------------------------------------------------------
// JSON emission
//
// Written by hand rather than with a JSON library: the repo has no JSON
// dependency, the shape is fixed by result_schema.json, and adding one for a
// few hundred bytes of output would not earn its place in the build.
// ---------------------------------------------------------------------------

std::string num(double v) {
    std::ostringstream os;
    os << std::setprecision(9) << v;
    return os.str();
}

void write_stats(std::ostream& os, const char* name, const Stats& s, const char* indent) {
    os << indent << "\"" << name << "\": { "
       << "\"mean\": " << num(s.mean) << ", "
       << "\"min\": " << num(s.min) << ", "
       << "\"max\": " << num(s.max) << ", "
       << "\"stddev\": " << num(s.stddev) << " }";
}

void write_json(std::ostream& os, const Options& opt, const Measurement& m) {
    const size_t signers = opt.t + 1;
    const double throughput = m.sign.mean > 0.0 ? 1000.0 / m.sign.mean : 0.0;

    os << "{\n";
    os << "  \"schema_version\": 1,\n";
    os << "  \"implementation\": \"tr-ecdsa\",\n";
    os << "  \"protocol_name\": \"TR-ECDSA (3-round, CL-HSM)\",\n";
    os << "  \"git_commit\": \"" << opt.git_commit << "\",\n";
    os << "  \"security\": {\n";
    os << "    \"label\": \"" << opt.level << "\",\n";
    os << "    \"enc_scheme\": \"CL_HSMqk\",\n";
    // CL-HSM security rests on class-group order, not on a modulus, so this is
    // "not applicable" rather than "unmeasured" (SCHEMA.md, security section).
    os << "    \"enc_modulus_bits\": null\n";
    os << "  },\n";
    os << "  \"params\": { \"n\": " << opt.n << ", \"t\": " << opt.t
       << ", \"signers\": " << signers << " },\n";
    os << "  \"trials\": { \"setup_trials\": " << opt.setup_trials
       << ", \"dkg_trials\": " << opt.dkg_trials
       << ", \"sign_trials\": " << opt.sign_trials << " },\n";
    os << "  \"timing_ms\": {\n";
    write_stats(os, "setup", m.setup, "    ");
    os << ",\n";
    write_stats(os, "dkg_or_keygen", m.dkg, "    ");
    os << ",\n";
    write_stats(os, "sign", m.sign, "    ");
    os << ",\n";
    write_stats(os, "verify", m.verify, "    ");
    os << "\n  },\n";
    os << "  \"throughput_sig_per_sec\": " << num(throughput) << ",\n";
    os << "  \"bandwidth_bytes\": {\n";
    os << "    \"total\": " << m.bandwidth.total_bytes << ",\n";
    os << "    \"per_party\": " << num(static_cast<double>(m.bandwidth.total_bytes)
                                       / static_cast<double>(signers)) << ",\n";
    os << "    \"per_round\": [\n";
    // Round 1 carries the CL ZKAoK proof, whose members are private to BICYCL
    // and so cannot be measured directly; it is computed from the proof's size
    // bound and tagged accordingly. Rounds 2 and 3 are counted exactly.
    os << "      { \"round_label\": \"round1\", \"bytes\": " << m.bandwidth.round1_bytes
       << ", \"exactness\": \"upper_bound_estimate\" },\n";
    os << "      { \"round_label\": \"round2\", \"bytes\": " << m.bandwidth.round2_bytes
       << ", \"exactness\": \"exact\" },\n";
    os << "      { \"round_label\": \"round3\", \"bytes\": " << m.bandwidth.round3_bytes
       << ", \"exactness\": \"exact\" }\n";
    os << "    ],\n";
    // Three native rounds here versus nine pattern-matched buckets in tss-lib:
    // the two are not aligned (SCHEMA.md caveat 1).
    os << "    \"per_round_comparable_across_impl\": false\n";
    os << "  },\n";
    os << "  \"object_sizes_bytes\": {\n";
    os << "    \"signature\": " << m.sizes.signature << ",\n";
    os << "    \"ec_public_key\": " << m.sizes.ec_public_key << ",\n";
    os << "    \"ec_key_share\": " << m.sizes.ec_key_share << ",\n";
    os << "    \"enc_public_key\": " << m.sizes.enc_public_key << ",\n";
    os << "    \"enc_key_share\": " << m.sizes.enc_key_share << ",\n";
    os << "    \"enc_ciphertext\": " << m.sizes.enc_ciphertext << "\n";
    os << "  },\n";
    os << "  \"correctness\": { \"all_signatures_valid\": "
       << (m.all_valid ? "true" : "false") << " },\n";
#if defined(__APPLE__)
    const char* os_name = "darwin";
#elif defined(__linux__)
    const char* os_name = "linux";
#elif defined(_WIN32)
    const char* os_name = "windows";
#else
    const char* os_name = "unknown";
#endif
    os << "  \"environment\": { \"os\": \"" << os_name
       << "\", \"impl_language\": \"cpp17\" },\n";
    os << "  \"notes\": \"\"\n";
    os << "}\n";
}

}  // namespace

int main(int argc, char** argv) {
    Options opt;
    if (!parse_args(argc, argv, opt)) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const std::optional<trecdsa::SecurityLevel> level = to_level(opt.level);
    if (!level) {
        std::cerr << "--level must be one of 112, 128, 192, 256\n";
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (opt.n == 0 || opt.t >= opt.n) {
        std::cerr << "require n > 0 and 0 <= t < n\n";
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    if (opt.sign_trials == 0 || opt.setup_trials == 0 || opt.dkg_trials == 0) {
        std::cerr << "trial counts must be positive\n";
        return EXIT_FAILURE;
    }

    try {
        const Measurement m = run_scenario(*level, opt);

        if (opt.out.empty()) {
            write_json(std::cout, opt, m);
        } else {
            std::ofstream file(opt.out);
            if (!file) {
                std::cerr << "cannot open output file: " << opt.out << "\n";
                return EXIT_FAILURE;
            }
            write_json(file, opt, m);
            if (!file) {
                std::cerr << "error writing output file: " << opt.out << "\n";
                return EXIT_FAILURE;
            }
        }

        // A correctness failure invalidates the timings printed beside it, so
        // it must be visible in the exit status and not only in the JSON.
        if (!m.all_valid) {
            std::cerr << "CORRECTNESS FAILURE: not all signatures verified\n";
            return EXIT_FAILURE;
        }
        return EXIT_SUCCESS;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return EXIT_FAILURE;
    }
}
