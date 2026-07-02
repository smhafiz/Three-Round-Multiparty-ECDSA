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

private:
    void validate_inputs(const std::set<size_t>& party_set,
                         const std::vector<unsigned char>& message) const;

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}

#endif
