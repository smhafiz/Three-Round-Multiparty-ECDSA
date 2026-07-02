#ifndef TRECDSA_BICYCL_UTILS_H
#define TRECDSA_BICYCL_UTILS_H

#include <set>

#include "bicycl_compat.h"

namespace utils {

inline BICYCL::Mpz factorial(size_t n) {
    BICYCL::Mpz result("1");
    for (size_t j = 2; j <= n; ++j) {
        BICYCL::Mpz::mul(result, result, j);
    }
    return result;
}

inline BICYCL::Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const BICYCL::Mpz& delta) {
    BICYCL::Mpz numerator("1"), denominator("1"), result;
    for (size_t j : S) {
        if (j != i) {
            BICYCL::Mpz::mul(numerator, numerator, j);
            if (j > i) {
                BICYCL::Mpz::mul(denominator, denominator, j - i);
            } else {
                BICYCL::Mpz::mul(denominator, denominator, i - j);
                denominator.neg();
            }
        }
    }
    BICYCL::Mpz::divexact(result, delta, denominator);
    BICYCL::Mpz::mul(result, result, numerator);
    return result;
}

// ---------------------------------------------------------------------------
// Serialized size helpers
// ---------------------------------------------------------------------------

inline size_t mpz_size_bytes(const BICYCL::Mpz& m) {
    return (m.nbits() + 7) / 8;
}

inline size_t qfi_size_bytes(const BICYCL::QFI& f) {
    return mpz_size_bytes(f.a()) + mpz_size_bytes(f.b());
}

inline size_t ciphertext_size_bytes(const BICYCL::CL_HSMqk::CipherText& ct) {
    return qfi_size_bytes(ct.c1()) + qfi_size_bytes(ct.c2());
}

// Compressed EC point: 1 byte prefix + ceil(order_bits / 8) bytes
inline size_t ecpoint_size_bytes(const BICYCL::OpenSSL::ECGroup& E) {
    return (E.order().nbits() + 7) / 8 + 1;
}

// ECNIZKProof stores (R: ECPoint, z: BN scalar mod q)
inline size_t ecnizkproof_size_bytes(const BICYCL::ECNIZKProof& proof,
                                     const BICYCL::OpenSSL::ECGroup& E) {
    return ecpoint_size_bytes(E)
           + (static_cast<BICYCL::Mpz>(proof.z()).nbits() + 7) / 8;
}

// Upper-bound estimate for CL_HSMqk_ZKAoKProof whose members are private.
// The proof stores (u1, u2, k): two responses bounded by the randomness bound
// scaled by soundness and lambda_distance bits, plus the hash challenge k.
inline size_t zkaok_size_bytes_estimate(const BICYCL::CL_HSMqk& cl,
                                        const BICYCL::HashAlgo& H) {
    BICYCL::Mpz bound(cl.encrypt_randomness_bound());
    BICYCL::Mpz::mulby2k(bound, bound, static_cast<size_t>(H.digest_nbits()));
    BICYCL::Mpz::mulby2k(bound, bound, cl.lambda_distance());
    return 2 * mpz_size_bytes(bound) + static_cast<size_t>(H.digest_nbytes());
}

// ---------------------------------------------------------------------------

inline BICYCL::OpenSSL::BN lagrange_at_zero(const BICYCL::OpenSSL::ECGroup& E,
                                            const std::set<size_t>& S,
                                            size_t i) {
    BICYCL::OpenSSL::BN numerator, denominator, result;
    numerator = 1UL;
    denominator = 1UL;
    for (size_t j : S) {
        if (j != i) {
            E.mul_by_word_mod_order(numerator, j);
            if (j > i) {
                E.mul_by_word_mod_order(denominator, j - i);
            } else {
                E.mul_by_word_mod_order(denominator, i - j);
                denominator.neg();
            }
        }
    }
    E.inverse_mod_order(result, denominator);
    E.mul_mod_order(result, result, numerator);
    return result;
}

}

#endif
