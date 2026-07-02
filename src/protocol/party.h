#ifndef TRECDSA_INTERNAL_PARTY_H
#define TRECDSA_INTERNAL_PARTY_H

#include <functional>
#include <optional>
#include <set>
#include <unordered_map>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Types.h>

#include "compat/bicycl_compat.h"

namespace trecdsa {

namespace OpenSSL = BICYCL::OpenSSL;

using Mpz = BICYCL::Mpz;
using QFI = BICYCL::QFI;
using RandGen = BICYCL::RandGen;
using CL_HSMqk = BICYCL::CL_HSMqk;
using ECNIZKProof = BICYCL::ECNIZKProof;
using CL_HSMqk_ZKAoKProof = BICYCL::CL_HSMqk_ZKAoKProof;
using CL_HSMqk_DL_CL_ZKProof = BICYCL::CL_HSMqk_DL_CL_ZKProof;
using CL_HSMqk_Part_Dec_ZKProof = BICYCL::CL_HSMqk_Part_Dec_ZKProof;

using Commitment = BICYCL::HashAlgo::Digest;
using CommitmentSecret = std::vector<unsigned char>;

struct RoundOneData {
    size_t id;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    RoundOneData(size_t id,
                 const CL_HSMqk::CipherText& share,
                 const Commitment& com_i,
                 const CL_HSMqk_ZKAoKProof& proof)
        : id(id), enc_phi_share(share), com_i(com_i), zk_proof_cl_enc(proof) {}

    size_t size_bytes(const GroupParams::Impl& p) const;
};

struct RoundOneLocalData {
    size_t id;
    OpenSSL::BN phi_share;
    OpenSSL::BN k_share;
    OpenSSL::ECPoint R_share;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CommitmentSecret open_i;
    std::unordered_map<size_t, Commitment> com_list;
    ECNIZKProof zk_proof_dl;

    RoundOneLocalData(size_t id,
                      const OpenSSL::ECGroup& E,
                      const OpenSSL::BN& phi,
                      const OpenSSL::BN& k,
                      const OpenSSL::ECPoint& R,
                      const CL_HSMqk::CipherText& ct,
                      const Commitment& com_i,
                      const CommitmentSecret& open_i,
                      const ECNIZKProof& zk_proof)
        : id(id),
          phi_share(phi),
          k_share(k),
          R_share(E, R),
          enc_phi_share(ct),
          com_i(com_i),
          open_i(open_i),
          zk_proof_dl(E, zk_proof) {
        com_list.emplace(this->id, com_i);
    }
};

struct RoundTwoData {
    size_t id;
    CL_HSMqk::CipherText phi_x_share;
    CL_HSMqk::CipherText phi_k_share;
    OpenSSL::ECPoint Ri;
    CommitmentSecret open_i;
    ECNIZKProof zk_proof_dl;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k;

    RoundTwoData(size_t id,
                 const OpenSSL::ECGroup& E,
                 const CL_HSMqk::CipherText& phi_x,
                 const CL_HSMqk::CipherText& phi_k,
                 const OpenSSL::ECPoint& R,
                 const CommitmentSecret& open_i,
                 const ECNIZKProof& zk_proof_dl,
                 const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_x,
                 const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_k)
        : id(id),
          phi_x_share(phi_x),
          phi_k_share(phi_k),
          Ri(E, R),
          open_i(open_i),
          zk_proof_dl(E, zk_proof_dl),
          zk_proof_dl_cl_x(E, zk_proof_dl_cl_x),
          zk_proof_dl_cl_k(E, zk_proof_dl_cl_k) {}

    size_t size_bytes(const GroupParams::Impl& p) const;
};

struct RoundTwoLocalData {
    size_t id;
    CL_HSMqk::CipherText enc_phi;

    RoundTwoLocalData(size_t id, const CL_HSMqk::CipherText& phi) : id(id), enc_phi(phi) {}
};

struct RoundThreeData {
    size_t id;
    QFI c0_dec_share;
    QFI c1_dec_share;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1;

    RoundThreeData(size_t id,
                   const QFI& c0_dec_share,
                   const QFI& c1_dec_share,
                   const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c0,
                   const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c1)
        : id(id),
          c0_dec_share(c0_dec_share),
          c1_dec_share(c1_dec_share),
          zk_proof_pd_c0(zk_proof_pd_c0),
          zk_proof_pd_c1(zk_proof_pd_c1) {}

    size_t size_bytes(const GroupParams::Impl& p) const;
};

struct RoundThreeLocalData {
    size_t id;
    CL_HSMqk::CipherText c0;
    CL_HSMqk::CipherText c1;
    OpenSSL::BN rx;

    RoundThreeLocalData(size_t id,
                        const CL_HSMqk::CipherText& c0,
                        const CL_HSMqk::CipherText& c1,
                        const OpenSSL::BN& rx)
        : id(id), c0(c0), c1(c1), rx(rx) {}
};

class Party {
public:
    Party(GroupParams& params,
          size_t id,
          CL_HSMqk::PublicKey class_group_public_key,
          const std::vector<CL_HSMqk::PublicKey>& class_group_public_key_shares,
          CL_HSMqk::SecretKey class_group_secret_key_share,
          const OpenSSL::ECPoint& ec_public_key,
          std::vector<OpenSSL::ECPoint>& ec_public_key_shares,
          OpenSSL::BN ec_secret_key_share);

    void set_party_set(const std::set<size_t>& party_set);

    RoundOneData handle_round_one();
    RoundTwoData handle_round_two(const std::vector<std::reference_wrapper<const RoundOneData>>& data);
    RoundThreeData handle_round_three(const std::vector<std::reference_wrapper<const RoundTwoData>>& data,
                                      const std::vector<unsigned char>& m);
    Signature handle_offline(const std::vector<std::reference_wrapper<const RoundThreeData>>& data);

private:
    std::tuple<Commitment, CommitmentSecret> commit(const OpenSSL::ECPoint& Q) const;
    bool open(const Commitment& c, const OpenSSL::ECPoint& Q, const CommitmentSecret& r) const;

    QFI partial_decrypt(const CL_HSMqk::SecretKey& secret_key,
                        const CL_HSMqk::CipherText& ciphertext) const;
    CL_HSMqk::ClearText aggregate_partial_ciphertext(const std::unordered_map<size_t, QFI>& pd_map,
                                                     const CL_HSMqk::CipherText& c) const;

    GroupParams& params_;
    size_t id_;
    CL_HSMqk::PublicKey class_group_public_key_;
    std::vector<CL_HSMqk::PublicKey> class_group_public_key_shares_;
    std::vector<OpenSSL::ECPoint> ec_public_key_shares_;
    OpenSSL::ECPoint ec_public_key_;
    CL_HSMqk::SecretKey class_group_secret_key_share_;
    OpenSSL::BN ec_secret_key_share_;
    std::set<size_t> active_party_set_;

    std::optional<RoundOneLocalData> round_one_local_data_;
    std::optional<RoundTwoLocalData> round_two_local_data_;
    std::optional<RoundThreeLocalData> round_three_local_data_;
};

}

#endif
