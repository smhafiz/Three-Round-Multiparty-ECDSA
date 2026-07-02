#include "party.h"

#include "compat/bicycl_utils.h"

namespace trecdsa {

size_t RoundOneData::size_bytes(const GroupParams::Impl& p) const {
    return utils::ciphertext_size_bytes(enc_phi_share)
           + com_i.size()
           + utils::zkaok_size_bytes_estimate(p.cl_pp, p.H);
}

size_t RoundTwoData::size_bytes(const GroupParams::Impl& p) const {
    return utils::ciphertext_size_bytes(phi_x_share)
           + utils::ciphertext_size_bytes(phi_k_share)
           + utils::ecpoint_size_bytes(p.ec_group)
           + open_i.size()
           + utils::ecnizkproof_size_bytes(zk_proof_dl, p.ec_group)
           + zk_proof_dl_cl_x.size_bytes(p.ec_group)
           + zk_proof_dl_cl_k.size_bytes(p.ec_group);
}

size_t RoundThreeData::size_bytes(const GroupParams::Impl& p) const {
    (void)p;
    return utils::qfi_size_bytes(c0_dec_share)
           + utils::qfi_size_bytes(c1_dec_share)
           + zk_proof_pd_c0.get_bytes()
           + zk_proof_pd_c1.get_bytes();
}

Party::Party(GroupParams& params,
             size_t id,
             CL_HSMqk::PublicKey class_group_public_key,
             const std::vector<CL_HSMqk::PublicKey>& class_group_public_key_shares,
             CL_HSMqk::SecretKey class_group_secret_key_share,
             const OpenSSL::ECPoint& ec_public_key,
             std::vector<OpenSSL::ECPoint>& ec_public_key_shares,
             OpenSSL::BN ec_secret_key_share)
    : params_(params),
      id_(id),
      class_group_public_key_(std::move(class_group_public_key)),
      class_group_public_key_shares_(class_group_public_key_shares),
      ec_public_key_(params.impl().ec_group, ec_public_key),
      class_group_secret_key_share_(std::move(class_group_secret_key_share)),
      ec_secret_key_share_(std::move(ec_secret_key_share)) {
    const size_t n = params_.impl().n;
    ec_public_key_shares_.reserve(n);
    for (size_t i = 0; i < n; ++i) {
        ec_public_key_shares_.emplace_back(params_.impl().ec_group, ec_public_key_shares[i]);
    }
}

void Party::set_party_set(const std::set<size_t>& party_set) {
    active_party_set_ = party_set;
}

std::tuple<Commitment, CommitmentSecret> Party::commit(const OpenSSL::ECPoint& Q) const {
    auto& p = params_.impl();
    const size_t nbytes = p.sec_level.nbits() / 8;
    CommitmentSecret r(nbytes);
    OpenSSL::random_bytes(r.data(), nbytes);
    return {p.H(r, OpenSSL::ECPointGroupCRefPair(Q, p.ec_group)), r};
}

bool Party::open(const Commitment& c, const OpenSSL::ECPoint& Q, const CommitmentSecret& r) const {
    auto& p = params_.impl();
    Commitment c2(p.H(r, OpenSSL::ECPointGroupCRefPair(Q, p.ec_group)));
    return c == c2;
}

RoundOneData Party::handle_round_one() {
    auto& p = params_.impl();
    RandGen randgen;

    OpenSSL::BN phi_share = p.ec_group.random_mod_order(randgen);
    OpenSSL::BN k_share = p.ec_group.random_mod_order(randgen);
    OpenSSL::ECPoint R_share(p.ec_group, k_share);
    Mpz r(randgen.random_mpz(p.cl_pp.encrypt_randomness_bound()));
    CL_HSMqk::ClearText ct(p.cl_pp, static_cast<Mpz>(phi_share));
    CL_HSMqk::CipherText enc_phi_share = p.cl_pp.encrypt(class_group_public_key_, ct, r);

    auto [com_i, open_i] = commit(R_share);

    ECNIZKProof zk_proof_dl(p.ec_group, p.H, randgen, k_share);
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc(p.cl_pp, p.H, class_group_public_key_, enc_phi_share, ct,
                                        r, randgen);

    round_one_local_data_.emplace(id_, p.ec_group, phi_share, k_share, R_share, enc_phi_share,
                                  com_i, open_i, zk_proof_dl);
    return RoundOneData(id_, enc_phi_share, com_i, zk_proof_cl_enc);
}

RoundTwoData Party::handle_round_two(
    const std::vector<std::reference_wrapper<const RoundOneData>>& data) {
    auto& p = params_.impl();
    RandGen randgen;

    const size_t valid_count = static_cast<size_t>(
        std::count_if(data.begin(), data.end(), [&](const auto& item) {
            const RoundOneData& d = item.get();
            return d.zk_proof_cl_enc.verify(p.cl_pp, p.H, class_group_public_key_,
                                            d.enc_phi_share);
        }));

    if (valid_count < p.t + 1) {
        throw ProtocolError("Party " + std::to_string(id_) +
                            ": zkps are not up to threshold in round 2");
    }

    CL_HSMqk::CipherText enc_phi = data[0].get().enc_phi_share;
    round_one_local_data_->com_list.reserve(data.size());
    round_one_local_data_->com_list.emplace(data[0].get().id, data[0].get().com_i);

    for (size_t i = 1; i < data.size(); ++i) {
        const RoundOneData& round_data = data[i].get();
        enc_phi =
            p.cl_pp.add_ciphertexts(class_group_public_key_, enc_phi, round_data.enc_phi_share,
                                    Mpz("0"));
        round_one_local_data_->com_list.emplace(round_data.id, round_data.com_i);
    }

    OpenSSL::BN omega = utils::lagrange_at_zero(p.ec_group, active_party_set_, id_);
    p.ec_group.mul_mod_order(omega, omega, ec_secret_key_share_);
    OpenSSL::ECPoint Xi(p.ec_group, omega);

    CL_HSMqk::CipherText phi_x_share = p.cl_pp.scal_ciphertexts(
        class_group_public_key_, enc_phi, static_cast<Mpz>(omega), Mpz("0"));
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x(
        p.cl_pp, p.ec_group, p.H, OpenSSL::ECPoint(p.ec_group, Xi), enc_phi, phi_x_share,
        CL_HSMqk::ClearText(p.cl_pp, static_cast<Mpz>(omega)), randgen);

    CL_HSMqk::CipherText phi_k_share = p.cl_pp.scal_ciphertexts(
        class_group_public_key_, enc_phi,
        static_cast<Mpz>(round_one_local_data_->k_share), Mpz("0"));
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k(
        p.cl_pp, p.ec_group, p.H,
        OpenSSL::ECPoint(p.ec_group, round_one_local_data_->R_share), enc_phi, phi_k_share,
        CL_HSMqk::ClearText(p.cl_pp, static_cast<Mpz>(round_one_local_data_->k_share)), randgen);

    round_two_local_data_.emplace(id_, enc_phi);
    return RoundTwoData(id_, p.ec_group, phi_x_share, phi_k_share, round_one_local_data_->R_share,
                        round_one_local_data_->open_i, round_one_local_data_->zk_proof_dl,
                        zk_proof_dl_cl_x, zk_proof_dl_cl_k);
}

RoundThreeData Party::handle_round_three(
    const std::vector<std::reference_wrapper<const RoundTwoData>>& data,
    const std::vector<unsigned char>& m) {
    auto& p = params_.impl();
    RandGen randgen;

    const size_t valid_count = static_cast<size_t>(
        std::count_if(data.begin(), data.end(), [&](const auto& item) {
            const RoundTwoData& d = item.get();
            OpenSSL::ECPoint Xi(p.ec_group, ec_public_key_shares_[d.id - 1]);
            p.ec_group.scal_mul(Xi, utils::lagrange_at_zero(p.ec_group, active_party_set_, d.id),
                                Xi);
            return open(round_one_local_data_->com_list[d.id], d.Ri, d.open_i) &&
                   d.zk_proof_dl.verify(p.ec_group, p.H, d.Ri) &&
                   d.zk_proof_dl_cl_x.verify(p.cl_pp, p.ec_group, p.H,
                                             OpenSSL::ECPoint(p.ec_group, Xi),
                                             round_two_local_data_->enc_phi, d.phi_x_share) &&
                   d.zk_proof_dl_cl_k.verify(p.cl_pp, p.ec_group, p.H,
                                             OpenSSL::ECPoint(p.ec_group, d.Ri),
                                             round_two_local_data_->enc_phi, d.phi_k_share);
        }));

    if (valid_count < p.t + 1) {
        throw ProtocolError("Party " + std::to_string(id_) + ": not up to threshold in round 3");
    }

    OpenSSL::ECPoint R(p.ec_group, data[0].get().Ri);
    CL_HSMqk::CipherText c0 = data[0].get().phi_k_share;
    CL_HSMqk::CipherText c1_r = data[0].get().phi_x_share;

    for (size_t i = 1; i < data.size(); ++i) {
        const RoundTwoData& round_data = data[i].get();
        p.ec_group.ec_add(R, R, round_data.Ri);
        c0 = p.cl_pp.add_ciphertexts(class_group_public_key_, c0, round_data.phi_k_share,
                                     Mpz("0"));
        c1_r = p.cl_pp.add_ciphertexts(class_group_public_key_, c1_r, round_data.phi_x_share,
                                       Mpz("0"));
    }

    OpenSSL::BN rx;
    p.ec_group.x_coord_of_point(rx, R);
    p.ec_group.mod_order(rx, rx);

    c1_r = p.cl_pp.scal_ciphertexts(class_group_public_key_, c1_r, static_cast<Mpz>(rx), Mpz("0"));
    OpenSSL::BN h(p.H(m));
    CL_HSMqk::CipherText c1_l = p.cl_pp.scal_ciphertexts(
        class_group_public_key_, round_two_local_data_->enc_phi, static_cast<Mpz>(h), Mpz("0"));
    CL_HSMqk::CipherText c1 =
        p.cl_pp.add_ciphertexts(class_group_public_key_, c1_l, c1_r, Mpz("0"));

    QFI part_c0_dec_share = partial_decrypt(class_group_secret_key_share_, c0);
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0(p.cl_pp, p.H,
                                             class_group_public_key_shares_[id_ - 1], c0,
                                             part_c0_dec_share, class_group_secret_key_share_,
                                             randgen);
    QFI part_c1_dec_share = partial_decrypt(class_group_secret_key_share_, c1);
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1(p.cl_pp, p.H,
                                             class_group_public_key_shares_[id_ - 1], c1,
                                             part_c1_dec_share, class_group_secret_key_share_,
                                             randgen);

    round_three_local_data_.emplace(id_, c0, c1, rx);
    return RoundThreeData(id_, part_c0_dec_share, part_c1_dec_share, zk_proof_pd_c0, zk_proof_pd_c1);
}

Signature Party::handle_offline(
    const std::vector<std::reference_wrapper<const RoundThreeData>>& data) {
    auto& p = params_.impl();

    const size_t valid_count = static_cast<size_t>(
        std::count_if(data.begin(), data.end(), [&](const auto& item) {
            const RoundThreeData& d = item.get();
            return d.zk_proof_pd_c0.verify(p.cl_pp, p.H,
                                           class_group_public_key_shares_[d.id - 1],
                                           round_three_local_data_->c0, d.c0_dec_share) &&
                   d.zk_proof_pd_c1.verify(p.cl_pp, p.H,
                                           class_group_public_key_shares_[d.id - 1],
                                           round_three_local_data_->c1, d.c1_dec_share);
        }));

    if (valid_count < p.t + 1) {
        throw ProtocolError("Party " + std::to_string(id_) +
                            ": not up to threshold in generating signatures");
    }

    std::unordered_map<size_t, QFI> part_c0_dec_shares;
    std::unordered_map<size_t, QFI> part_c1_dec_shares;
    part_c0_dec_shares.reserve(data.size());
    part_c1_dec_shares.reserve(data.size());

    for (const auto& item : data) {
        const RoundThreeData& round_data = item.get();
        part_c0_dec_shares[round_data.id] = round_data.c0_dec_share;
        part_c1_dec_shares[round_data.id] = round_data.c1_dec_share;
    }

    CL_HSMqk::ClearText m0 =
        aggregate_partial_ciphertext(part_c0_dec_shares, round_three_local_data_->c0);
    CL_HSMqk::ClearText m1 =
        aggregate_partial_ciphertext(part_c1_dec_shares, round_three_local_data_->c1);

    OpenSSL::BN m0_bn(m0);
    OpenSSL::BN m1_bn(m1);
    OpenSSL::BN inv_m0;
    OpenSSL::BN s;
    p.ec_group.inverse_mod_order(inv_m0, m0_bn);
    p.ec_group.mul_mod_order(s, inv_m0, m1_bn);

    Signature sig;
    sig.impl_ = std::make_unique<Signature::Impl>(round_three_local_data_->rx, s);
    return sig;
}

QFI Party::partial_decrypt(const CL_HSMqk::SecretKey& secret_key,
                           const CL_HSMqk::CipherText& ciphertext) const {
    auto& p = params_.impl();
    Mpz sk_mpz(secret_key);
    Mpz::mod(sk_mpz, sk_mpz, p.cl_pp.secretkey_bound());

    QFI fm;
    p.cl_pp.Cl_G().nupow(fm, ciphertext.c1(), sk_mpz);
    if (p.cl_pp.compact_variant()) {
        p.cl_pp.from_Cl_DeltaK_to_Cl_Delta(fm);
    }
    return fm;
}

CL_HSMqk::ClearText Party::aggregate_partial_ciphertext(
    const std::unordered_map<size_t, QFI>& pd_map, const CL_HSMqk::CipherText& c) const {
    auto& p = params_.impl();

    if (pd_map.size() <= p.t) {
        throw ProtocolError("Insufficient shares for aggregation.");
    }

    QFI c2 = c.c2();
    for (size_t s : active_party_set_) {
        QFI num;
        p.cl_pp.Cl_G().nupow(num, pd_map.at(s),
                             utils::cl_lagrange_at_zero(active_party_set_, s, p.delta));
        p.cl_pp.Cl_Delta().nucompinv(c2, c2, num);
    }
    return CL_HSMqk::ClearText(p.cl_pp, p.cl_pp.dlog_in_F(c2));
}

}
