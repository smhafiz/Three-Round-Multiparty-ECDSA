#include <set>
#include <vector>

#include <trecdsa/Protocol.h>

#include "compat/bicycl_utils.h"
#include "party.h"

namespace trecdsa {

namespace OpenSSL = BICYCL::OpenSSL;

struct Protocol::Impl {
    explicit Impl(GroupParams& params)
        : params(params), sig_public_key(OpenSSL::ECPoint(params.impl().ec_group)) {
        parties.reserve(params.impl().n);
    }

    GroupParams& params;
    OpenSSL::ECPoint sig_public_key;
    std::vector<Party> parties;
    BandwidthStats bw{};
};

Protocol::Protocol(GroupParams& params) : impl_(std::make_unique<Impl>(params)) {}
Protocol::~Protocol() = default;
Protocol::Protocol(Protocol&& other) noexcept = default;
Protocol& Protocol::operator=(Protocol&& other) noexcept = default;

void Protocol::run_dkg() {
    auto& p = impl_->params.impl();
    RandGen randgen;

    const size_t n = p.n;
    const size_t t = p.t;

    // Coefficient bound derived from secretkey_bound (accommodates up to n=20, t=19)
    const size_t ell = p.cl_pp.secretkey_bound().nbits() - 124;
    Mpz coeff_bound;
    Mpz::mulby2k(coeff_bound, Mpz("1"), ell);

    std::vector<CL_HSMqk::SecretKey> sk_list;
    std::vector<CL_HSMqk::PublicKey> pk_list;
    sk_list.reserve(n);
    pk_list.reserve(n);

    Mpz alpha(randgen.random_mpz(coeff_bound));
    Mpz cl_u;
    Mpz sk;
    Mpz::mul(cl_u, alpha, p.delta);
    Mpz::mul(sk, cl_u, p.delta);

    CL_HSMqk::SecretKey sk_delta(p.cl_pp, sk);
    CL_HSMqk::PublicKey pk = p.cl_pp.keygen(sk_delta);

    std::vector<Mpz> cl_coefficients;
    cl_coefficients.reserve(t);
    for (size_t k = 0; k < t; ++k) {
        cl_coefficients.emplace_back(randgen.random_mpz(coeff_bound));
    }

    for (size_t j = 0; j < n; ++j) {
        Mpz skj = cl_coefficients[t - 1];
        for (size_t k = t - 1; k > 0; --k) {
            Mpz::mul(skj, skj, Mpz(j + 1));
            Mpz::add(skj, skj, cl_coefficients[k - 1]);
        }
        Mpz::mul(skj, skj, Mpz(j + 1));
        Mpz::add(skj, skj, cl_u);
        sk_list.emplace_back(p.cl_pp, skj);
        pk_list.emplace_back(p.cl_pp, sk_list.back());
    }

    OpenSSL::BN u(p.ec_group.random_mod_order(randgen));
    OpenSSL::ECPoint X(p.ec_group, u);

    std::vector<OpenSSL::BN> ec_coefficients;
    ec_coefficients.reserve(t);
    for (size_t k = 0; k < t; ++k) {
        ec_coefficients.push_back(p.ec_group.random_mod_order(randgen));
    }

    std::vector<OpenSSL::BN> xi_list(n);
    for (size_t j = 0; j < n; ++j) {
        xi_list[j] = ec_coefficients[t - 1];
        for (size_t k = t - 1; k > 0; --k) {
            p.ec_group.mul_by_word_mod_order(xi_list[j], j + 1);
            p.ec_group.add_mod_order(xi_list[j], xi_list[j], ec_coefficients[k - 1]);
        }
        p.ec_group.mul_by_word_mod_order(xi_list[j], j + 1);
        p.ec_group.add_mod_order(xi_list[j], xi_list[j], u);
    }

    std::vector<OpenSSL::ECPoint> Xi_list;
    Xi_list.reserve(n);
    OpenSSL::ECPoint T(p.ec_group);
    for (const auto& xi : xi_list) {
        p.ec_group.scal_mul_gen(T, xi);
        Xi_list.emplace_back(p.ec_group, T);
    }

    impl_->parties.clear();
    impl_->parties.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        impl_->parties.emplace_back(impl_->params, i + 1, pk, pk_list, sk_list[i], X, Xi_list,
                                    xi_list[i]);
    }

    impl_->sig_public_key = OpenSSL::ECPoint(p.ec_group, X);
}

std::vector<Signature> Protocol::run(const std::set<size_t>& party_set,
                                     const std::vector<unsigned char>& message) {
    std::vector<Signature> signatures;
    run(party_set, message, signatures);
    return signatures;
}

void Protocol::run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message,
                   std::vector<Signature>& signatures_out) {
    validate_inputs(party_set, message);

    for (auto& party : impl_->parties) {
        party.set_party_set(party_set);
    }

    std::vector<RoundOneData> round_one_outputs;
    std::vector<std::reference_wrapper<const RoundOneData>> round_one_views;
    round_one_outputs.reserve(party_set.size());
    round_one_views.reserve(party_set.size());

    std::vector<RoundTwoData> round_two_outputs;
    std::vector<std::reference_wrapper<const RoundTwoData>> round_two_views;
    round_two_outputs.reserve(party_set.size());
    round_two_views.reserve(party_set.size());

    std::vector<RoundThreeData> round_three_outputs;
    std::vector<std::reference_wrapper<const RoundThreeData>> round_three_views;
    round_three_outputs.reserve(party_set.size());
    round_three_views.reserve(party_set.size());

    signatures_out.clear();
    signatures_out.reserve(party_set.size());

    for (auto& i : party_set) {
        round_one_outputs.push_back(impl_->parties[i - 1].handle_round_one());
    }
    for (const RoundOneData& data : round_one_outputs) {
        round_one_views.push_back(std::cref(data));
    }

    for (auto& i : party_set) {
        round_two_outputs.push_back(impl_->parties[i - 1].handle_round_two(round_one_views));
    }
    for (const RoundTwoData& data : round_two_outputs) {
        round_two_views.push_back(std::cref(data));
    }

    for (auto& i : party_set) {
        round_three_outputs.push_back(
            impl_->parties[i - 1].handle_round_three(round_two_views, message));
    }
    for (const RoundThreeData& data : round_three_outputs) {
        round_three_views.push_back(std::cref(data));
    }

    for (auto& i : party_set) {
        signatures_out.push_back(impl_->parties[i - 1].handle_offline(round_three_views));
    }

    const GroupParams::Impl& p = impl_->params.impl();
    BandwidthStats bw{};
    for (const auto& d : round_one_outputs)   bw.round1_bytes += d.size_bytes(p);
    for (const auto& d : round_two_outputs)   bw.round2_bytes += d.size_bytes(p);
    for (const auto& d : round_three_outputs) bw.round3_bytes += d.size_bytes(p);
    bw.total_bytes = bw.round1_bytes + bw.round2_bytes + bw.round3_bytes;
    impl_->bw = bw;
}

bool Protocol::verify(const std::vector<Signature>& signatures,
                      const std::vector<unsigned char>& message) const {
    if (impl_->parties.empty()) {
        throw ProtocolError("run_dkg must be called before verify");
    }
    if (signatures.empty()) {
        throw ProtocolError("signature set cannot be empty");
    }
    if (message.empty()) {
        throw ProtocolError("message cannot be empty");
    }

    auto& p = impl_->params.impl();
    OpenSSL::BN h(p.H(message));
    OpenSSL::BN inv_s;
    OpenSSL::BN u1;
    OpenSSL::BN u2;
    OpenSSL::ECPoint R(p.ec_group);

    bool valid = true;
    for (const auto& sig : signatures) {
        p.ec_group.inverse_mod_order(inv_s, sig.impl_->s);
        p.ec_group.mul_mod_order(u1, inv_s, h);
        p.ec_group.mul_mod_order(u2, inv_s, sig.impl_->rx);
        p.ec_group.scal_mul(R, u1, u2, impl_->sig_public_key);

        OpenSSL::BN rx;
        p.ec_group.x_coord_of_point(rx, R);
        p.ec_group.mod_order(rx, rx);
        valid &= (rx == sig.impl_->rx);
    }
    return valid;
}

void Protocol::validate_inputs(const std::set<size_t>& party_set,
                                const std::vector<unsigned char>& message) const {
    if (impl_->parties.empty()) {
        throw ProtocolError("run_dkg must be called before protocol execution");
    }
    if (party_set.size() < impl_->params.threshold() + 1) {
        throw ProtocolError("party set must contain at least threshold + 1 parties");
    }
    for (size_t party_id : party_set) {
        if (party_id < 1 || party_id > impl_->params.party_count()) {
            throw ProtocolError("party id is out of range");
        }
    }
    if (message.empty()) {
        throw ProtocolError("message cannot be empty");
    }
}

size_t Protocol::party_count() const noexcept {
    return impl_->params.party_count();
}

size_t Protocol::threshold() const noexcept {
    return impl_->params.threshold();
}

BandwidthStats Protocol::last_bandwidth() const noexcept {
    return impl_->bw;
}

}
