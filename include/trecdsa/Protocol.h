#ifndef TRECDSA_PROTOCOL_H
#define TRECDSA_PROTOCOL_H

#include <memory>
#include <set>
#include <vector>

#include <trecdsa/Errors.h>
#include <trecdsa/Types.h>

namespace trecdsa {

struct BandwidthStats {
    size_t round1_bytes = 0;
    size_t round2_bytes = 0;
    size_t round3_bytes = 0;
    size_t total_bytes  = 0;
};

// Serialized sizes of the individual objects a deployment would store or send.
// Sampled from the key material produced by run_dkg(), so the CL-side figures
// reflect actual values (whose bit lengths vary a little with n and with the
// random draw) rather than parameter-derived bounds.
struct ObjectSizes {
    size_t signature       = 0;  // r || s
    size_t ec_public_key   = 0;  // compressed point
    size_t ec_key_share    = 0;  // one party's secret EC share
    size_t enc_public_key  = 0;  // shared CL-HSM public key (a QFI)
    size_t enc_key_share   = 0;  // one party's share of the CL secret
    size_t enc_ciphertext  = 0;  // one CL-HSM ciphertext (two QFIs)
};

class Protocol {
public:
    explicit Protocol(GroupParams& params);
    ~Protocol();
    Protocol(Protocol&& other) noexcept;
    Protocol& operator=(Protocol&& other) noexcept;

    Protocol(const Protocol&) = delete;
    Protocol& operator=(const Protocol&) = delete;

    void run_dkg();
    std::vector<Signature> run(const std::set<size_t>& party_set,
                               const std::vector<unsigned char>& message);
    void run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message,
             std::vector<Signature>& signatures_out);
    bool verify(const std::vector<Signature>& signatures,
                const std::vector<unsigned char>& message) const;

    size_t party_count() const noexcept;
    size_t threshold() const noexcept;
    BandwidthStats last_bandwidth() const noexcept;

    // Valid only after run_dkg(); zero-initialized before it.
    ObjectSizes object_sizes() const noexcept;

private:
    void validate_inputs(const std::set<size_t>& party_set,
                         const std::vector<unsigned char>& message) const;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}

#endif
