#ifndef TRECDSA_BICYCL_COMPAT_H
#define TRECDSA_BICYCL_COMPAT_H

#include <stdexcept>

#include <openssl/rand.h>

#include <bicycl.hpp>

namespace BICYCL {

namespace OpenSSL {
using BN = ::BICYCL::BN;
using ECPoint = ::BICYCL::ECPoint;
using ECGroup = ::BICYCL::ECGroup;
using HashAlgo = ::BICYCL::HashAlgo;
using ECPointGroupCRefPair = ::BICYCL::ECPointGroupCRefPair;

inline void random_bytes(unsigned char* out, size_t out_len) {
    if (out_len == 0) {
        return;
    }
    if (RAND_bytes(out, static_cast<int>(out_len)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
}
}

class CL_HSMqk_Part_Dec_ZKProof {
public:
    CL_HSMqk_Part_Dec_ZKProof(const CL_HSMqk& cryptosystem,
                              HashAlgo& hash_algo,
                              const CL_HSMqk::PublicKey& public_key,
                              const CL_HSMqk::CipherText& ciphertext,
                              const QFI& partial_decryption,
                              const CL_HSMqk::SecretKey& secret_key,
                              RandGen& random_generator) {
        const int soundness = hash_algo.digest_nbits();

        Mpz randomness_bound(cryptosystem.encrypt_randomness_bound());
        Mpz::mulby2k(randomness_bound, randomness_bound, static_cast<size_t>(soundness));
        Mpz::mulby2k(randomness_bound, randomness_bound, cryptosystem.lambda_distance());

        Mpz witness(random_generator.random_mpz(randomness_bound));
        cryptosystem.power_of_h(t1_, witness);
        cryptosystem.Cl_G().nupow(t2_, ciphertext.c1(), witness);

        k_ = challenge_from_hash(hash_algo, public_key, ciphertext, partial_decryption, t1_, t2_);
        Mpz::mul(z_, k_, secret_key);
        Mpz::add(z_, z_, witness);
    }

    bool verify(const CL_HSMqk& cryptosystem,
                HashAlgo&,
                const CL_HSMqk::PublicKey& public_key,
                const CL_HSMqk::CipherText& ciphertext,
                const QFI& partial_decryption) const {
        QFI lhs_1;
        QFI rhs_1;
        cryptosystem.power_of_h(lhs_1, z_);

        public_key.exponentiation(cryptosystem, rhs_1, k_);
        if (cryptosystem.compact_variant()) {
            cryptosystem.from_Cl_DeltaK_to_Cl_Delta(rhs_1);
        }
        cryptosystem.Cl_G().nucomp(rhs_1, rhs_1, t1_);
        if (!(lhs_1 == rhs_1)) {
            return false;
        }

        QFI lhs_2;
        QFI rhs_2;
        cryptosystem.Cl_G().nupow(lhs_2, ciphertext.c1(), z_);
        cryptosystem.Cl_G().nupow(rhs_2, partial_decryption, k_);
        cryptosystem.Cl_G().nucomp(rhs_2, rhs_2, t2_);
        return lhs_2 == rhs_2;
    }

    size_t get_bytes() const {
        const auto mpz_b = [](const Mpz& m) { return (m.nbits() + 7) / 8; };
        return mpz_b(z_) + mpz_b(k_)
               + mpz_b(t1_.a()) + mpz_b(t1_.b())
               + mpz_b(t2_.a()) + mpz_b(t2_.b());
    }

private:
    static Mpz challenge_from_hash(HashAlgo& hash_algo,
                                   const CL_HSMqk::PublicKey& public_key,
                                   const CL_HSMqk::CipherText& ciphertext,
                                   const QFI& partial_decryption,
                                   const QFI& t1,
                                   const QFI& t2) {
        return Mpz(hash_algo(ciphertext, public_key, partial_decryption, t1, t2));
    }

    QFI t1_;
    QFI t2_;
    Mpz k_;
    Mpz z_;
};

class CL_HSMqk_DL_CL_ZKProof {
public:
    CL_HSMqk_DL_CL_ZKProof(const OpenSSL::ECGroup& ec_group, const CL_HSMqk_DL_CL_ZKProof& other)
        : z1_(other.z1_), k_(other.k_), t1_(other.t1_), t2_(other.t2_), s_(ec_group, other.s_) {}

    CL_HSMqk_DL_CL_ZKProof(const CL_HSMqk& cryptosystem,
                           const OpenSSL::ECGroup& ec_group,
                           HashAlgo& hash_algo,
                           const OpenSSL::ECPoint& ec_public_key,
                           const CL_HSMqk::CipherText& ciphertext_0,
                           const CL_HSMqk::CipherText& ciphertext_1,
                           const CL_HSMqk::ClearText& witness,
                           RandGen& random_generator)
        : s_(ec_group) {
        const int soundness = hash_algo.digest_nbits();

        Mpz randomness_bound(cryptosystem.encrypt_randomness_bound());
        Mpz::mulby2k(randomness_bound, randomness_bound, static_cast<size_t>(soundness));
        Mpz::mulby2k(randomness_bound, randomness_bound, cryptosystem.lambda_distance());

        Mpz nonce(random_generator.random_mpz(randomness_bound));
        ec_group.scal_mul_gen(s_, OpenSSL::BN(nonce));

        cryptosystem.Cl_G().nupow(t1_, ciphertext_0.c1(), nonce);
        cryptosystem.Cl_Delta().nupow(t2_, ciphertext_0.c2(), nonce);

        k_ = challenge_from_hash(hash_algo, ec_public_key, ciphertext_0, ciphertext_1, t1_, t2_);
        Mpz::mul(z1_, k_, witness);
        Mpz::add(z1_, z1_, nonce);
    }

    bool verify(const CL_HSMqk& cryptosystem,
                const OpenSSL::ECGroup& ec_group,
                HashAlgo&,
                const OpenSSL::ECPoint& ec_public_key,
                const CL_HSMqk::CipherText& ciphertext_0,
                const CL_HSMqk::CipherText& ciphertext_1) const {
        bool valid = true;

        QFI lhs_1;
        QFI rhs_1;
        QFI lhs_2;
        QFI rhs_2;

        cryptosystem.Cl_G().nupow(lhs_1, ciphertext_0.c1(), z1_);
        cryptosystem.Cl_G().nupow(rhs_1, ciphertext_1.c1(), k_);
        cryptosystem.Cl_G().nucomp(rhs_1, rhs_1, t1_);
        valid &= (lhs_1 == rhs_1);

        cryptosystem.Cl_Delta().nupow(lhs_2, ciphertext_0.c2(), z1_);
        cryptosystem.Cl_Delta().nupow(rhs_2, ciphertext_1.c2(), k_);
        cryptosystem.Cl_Delta().nucomp(rhs_2, rhs_2, t2_);
        valid &= (lhs_2 == rhs_2);

        OpenSSL::ECPoint lhs_3(ec_group, OpenSSL::BN(z1_));
        OpenSSL::ECPoint rhs_3(ec_group, ec_public_key);
        ec_group.scal_mul(rhs_3, OpenSSL::BN(k_), rhs_3);
        ec_group.ec_add(rhs_3, rhs_3, s_);
        valid &= ec_group.ec_point_eq(lhs_3, rhs_3);

        return valid;
    }

    // Serialized: z1 + k (Mpz scalars) + t1 + t2 (QFI each = a,b) + s (compressed ECPoint)
    size_t size_bytes(const OpenSSL::ECGroup& E) const {
        const auto mpz_b = [](const Mpz& m) { return (m.nbits() + 7) / 8; };
        return mpz_b(z1_) + mpz_b(k_)
               + mpz_b(t1_.a()) + mpz_b(t1_.b())
               + mpz_b(t2_.a()) + mpz_b(t2_.b())
               + (E.order().nbits() + 7) / 8 + 1;
    }

private:
    static Mpz challenge_from_hash(HashAlgo& hash_algo,
                                   const OpenSSL::ECPoint&,
                                   const CL_HSMqk::CipherText& ciphertext_0,
                                   const CL_HSMqk::CipherText& ciphertext_1,
                                   const QFI& t1,
                                   const QFI& t2) {
        return Mpz(hash_algo(ciphertext_0, ciphertext_1, t1, t2));
    }


    Mpz z1_;
    Mpz k_;
    QFI t1_;
    QFI t2_;
    OpenSSL::ECPoint s_;
};

}

#endif
