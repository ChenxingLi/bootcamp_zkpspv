//
// Created by lylcx-mac on 2017/7/17.
//

#ifndef BOOTCAMP_ZKPSPV_ZKSPV_LM_HPP
#define BOOTCAMP_ZKPSPV_ZKSPV_LM_HPP

#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp"
#include "tool.h"
#include <vector>

#ifdef CODE_READ
using namespace libsnark;
#endif

#define TIMESTAMPS 11
#define MSG_LEN (256+256+11*32)

namespace libsnark {
    template<typename FieldT>
    class zkspv_pcd_message : public r1cs_pcd_message<FieldT> {
    public:
        std::vector<uint8_t> unpacked_data;

        uint256 rt;
        uint256 preHash;
        std::vector<uint32_t> timestamp;

        size_t capacity;

        zkspv_pcd_message(const size_t type, uint256 preHash, uint256 rt, std::vector<uint32_t> &t) :
                r1cs_pcd_message<FieldT>(type),
                preHash(preHash),
                rt(rt),
                timestamp(t.begin(), t.end()) {
            capacity = FieldT::capacity();
            unpacked_data.insert(unpacked_data.end(), rt.begin(), rt.end());
            unpacked_data.insert(unpacked_data.end(), preHash.begin(), preHash.end());

            std::vector<uint8_t> bytetimestamp(4 * TIMESTAMPS);
            memcpy(&(bytetimestamp[0]), &(timestamp[0]), 4 * TIMESTAMPS);
            unpacked_data.insert(unpacked_data.end(), bytetimestamp.begin(), bytetimestamp.end());
            ASSERT(unpacked_data.size() == MSG_LEN / 8, "Invaild input length");
        }

        r1cs_variable_assignment<FieldT> payload_as_r1cs_variable_assignment() const {
            size_t count = 0;
            r1cs_variable_assignment<FieldT> result;
            FieldT base = FieldT::one();
            FieldT sum = FieldT::zero();
            for (std::vector<uint8_t>::const_iterator it = unpacked_data.begin(); it != unpacked_data.end(); it++) {
                for (size_t i = 0; i < 8; i++) {
                    sum += ((*it) >> i & 0x1 ? base : FieldT::zero());
                    count++;
                    base += base;
                    if (count == capacity) {
                        count = 0;
                        base = FieldT::one();
                        result.push_back(sum);
                        sum = FieldT::zero();
                    }
                }
            }
            if (count != 0) {
                result.push_back(sum);
            }
            assert(result.size() == div_ceil(unpacked_data.size() * 8, capacity));
            return result;
        }

        void print() const {
            return;
        }

        ~zkspv_pcd_message() = default;
    };

    template<typename FieldT>
    class zkspv_pcd_local_data : public r1cs_pcd_local_data<FieldT> {
    public:
        BlockHeader header;

        zkspv_pcd_local_data(BlockHeader header) : header(header) {}

        r1cs_variable_assignment<FieldT> as_r1cs_variable_assignment() const {
            size_t count = 0;
            r1cs_variable_assignment<FieldT> result;
            FieldT base = FieldT::one();
            FieldT sum = FieldT::zero();
            for (const uint8_t *p = header.begin(); p != header.end(); p++) {
                for (size_t i = 0; i < 8; i++) {
                    sum += ((*p) >> i & 0x1 ? base : FieldT::zero());
                    base += base;
                }
                count++;
                if (count == 4) {
                    count = 0;
                    result.push_back(sum);
                    sum = FieldT::zero();
                    base = FieldT::one();
                }
            }
            assert(result.size() == 20);
            return result;
        }

        void print() const {
            return;
        }

        ~zkspv_pcd_local_data() = default;
    };

    template<typename FieldT>
    class zkspv_pcd_message_variable : public r1cs_pcd_message_variable<FieldT> {
    public:
        pb_variable_array<FieldT> packed_message;

        zkspv_pcd_message_variable(protoboard<FieldT> &pb,
                                   const size_t capacity,
                                   const std::string &annotation_prefix) :
                r1cs_pcd_message_variable<FieldT>(pb, annotation_prefix) {
            packed_message.allocate(pb, div_ceil(MSG_LEN, capacity), FMT(annotation_prefix, " packed message"));
            this->update_all_vars();
        }

        std::shared_ptr<r1cs_pcd_message<FieldT> > get_message() const {
            ASSERT(false, "This class don't compute message, compute it by yourself.");
            return nullptr;
        }

        ~zkspv_pcd_message_variable() = default;
    };

    template<typename FieldT>
    class zkspv_pcd_local_data_variable : public r1cs_pcd_local_data_variable<FieldT> {
    public:

        pb_variable_array<FieldT> packed_local_data;

        zkspv_pcd_local_data_variable(protoboard<FieldT> &pb,
                                      const std::string &annotation_prefix) :
                r1cs_pcd_local_data_variable<FieldT>(pb, annotation_prefix) {
            packed_local_data.allocate(pb, 20, FMT(annotation_prefix, " packed local data"));
            this->update_all_vars();
        }

        std::shared_ptr<r1cs_pcd_local_data<FieldT> > get_local_data() const {
            ASSERT(false, "This class don't compute local data, compute it by yourself.");
            return nullptr;
        }

        ~zkspv_pcd_local_data_variable() = default;
    };

    template<typename FieldT>
    class zkspv_message_packer : public gadget<FieldT> {
    public:
        pb_variable_array<FieldT> repacked;
        size_t capacity;


        pb_variable_array<FieldT> fully_packed;
        pb_variable_array<FieldT> unpacked;

        std::shared_ptr<multipacking_gadget<FieldT> > unpacker;
        std::shared_ptr<multipacking_gadget<FieldT> > repacker;
    public:
        zkspv_message_packer(protoboard<FieldT> &pb,
                             pb_variable_array<FieldT> &fully_packed_in,
                             size_t capacity,
                             const std::string &annotation_prefix) :
                gadget<FieldT>(pb, annotation_prefix), capacity(capacity),
                fully_packed(fully_packed_in) {
            unpacked.allocate(pb, MSG_LEN, " unpacked message");
            repacked.allocate(pb, MSG_LEN / 32, " repacked message");
            unpacker.reset(new multipacking_gadget<FieldT>(pb, unpacked, fully_packed, capacity,
                                                           FMT(this->annotation_prefix, " message fully packer")));
            repacker.reset(new multipacking_gadget<FieldT>(pb, unpacked, repacked, 32,
                                                           FMT(this->annotation_prefix, " message re-packer")));
        }

        void generate_r1cs_constraints() {
            unpacker->generate_r1cs_constraints(true);
            repacker->generate_r1cs_constraints(false);
        }

        void generate_r1cs_witness() {
            unpacker->generate_r1cs_witness_from_packed();
            repacker->generate_r1cs_witness_from_bits();
        }
    };
}


#endif //BOOTCAMP_ZKPSPV_SPV_SPCP_HPP
