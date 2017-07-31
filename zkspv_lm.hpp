//
// Created by lylcx-mac on 2017/7/17.
//

#ifndef BOOTCAMP_ZKPSPV_ZKSPV_LM_HPP
#define BOOTCAMP_ZKPSPV_ZKSPV_LM_HPP

#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp"
#include "tool.h"
#include <iostream>
#include <vector>
#include <boost/foreach.hpp>

#define BATCH 2

#ifdef CODE_READ
using namespace libsnark;
#endif

#define TIMESTAMPS 11
#define MSG_LEN (256+256+11*32 + 32)

namespace libsnark {
    template<typename FieldT>
    class zkspv_pcd_message : public r1cs_pcd_message<FieldT> {
    public:
        std::vector <uint8_t> unpacked_data;

        uint256 preHash;
        std::vector <uint32_t> timestamp;
        uint256 rt;
        uint32_t empty;

        size_t capacity;

        zkspv_pcd_message(const size_t type, uint256 preHash, uint256 rt, std::vector <uint32_t> &t) :
                r1cs_pcd_message<FieldT>(type),
                rt(rt),
                preHash(preHash),
                timestamp(t.begin(), t.end()),
                empty(0) {
            capacity = FieldT::capacity();

            unpacked_data.insert(unpacked_data.end(), preHash.begin(), preHash.end());

            std::vector <uint8_t> bytetimestamp(4 * TIMESTAMPS);
            memcpy(&(bytetimestamp[0]), &(timestamp[0]), 4 * TIMESTAMPS);
            unpacked_data.insert(unpacked_data.end(), bytetimestamp.begin(), bytetimestamp.end());

            unpacked_data.insert(unpacked_data.end(), rt.begin(), rt.end());

            std::vector <uint8_t> byteempty(4);
            memcpy(&(byteempty[0]), &empty, 4);

            unpacked_data.insert(unpacked_data.end(), byteempty.begin(), byteempty.end());

            ASSERT(unpacked_data.size() == MSG_LEN / 8, "Invaild input length");
        }

        r1cs_variable_assignment <FieldT> payload_as_r1cs_variable_assignment() const {
            size_t count = 0;
            r1cs_variable_assignment <FieldT> result;
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
        boost::array<BlockHeader, BATCH> header;

        zkspv_pcd_local_data(boost::array<BlockHeader, BATCH> header) : header(header) {}

        r1cs_variable_assignment <FieldT> as_r1cs_variable_assignment() const {
            r1cs_variable_assignment <FieldT> result;
            FieldT base = FieldT::one();
            FieldT sum = FieldT::zero();
            for (size_t k = 0; k < BATCH; k++) {
                for (const uint8_t *p = header[k].begin(); p != header[k].end(); p += 4) {
                    for (size_t j = 0; j < 4; j++) {
                        for (size_t i = 0; i < 8; i++) {
                            bool bit = (*(p + 3 - j) >> i) & 0x1;
                            sum += bit ? base : FieldT::zero();
                            base += base;
                        }
                    }
                    result.push_back(sum);
                    sum = FieldT::zero();
                    base = FieldT::one();
                }
            }
            assert(result.size() == 20 * BATCH);
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
        pb_variable_array <FieldT> packed_message;

        zkspv_pcd_message_variable(protoboard <FieldT> &pb,
                                   const size_t capacity,
                                   const std::string &annotation_prefix) :
                r1cs_pcd_message_variable<FieldT>(pb, annotation_prefix) {
            packed_message.allocate(pb, div_ceil(MSG_LEN, capacity), FMT(annotation_prefix, " packed message"));
            this->update_all_vars();
        }

        std::shared_ptr <r1cs_pcd_message<FieldT>> get_message() const {
            ASSERT(false, "This class don't compute message, compute it by yourself.");
            return nullptr;
        }

        ~zkspv_pcd_message_variable() = default;
    };

    template<typename FieldT>
    class zkspv_pcd_local_data_variable : public r1cs_pcd_local_data_variable<FieldT> {
    public:

        pb_variable_array <FieldT> packed_local_data;

        zkspv_pcd_local_data_variable(protoboard <FieldT> &pb,
                                      const std::string &annotation_prefix) :
                r1cs_pcd_local_data_variable<FieldT>(pb, annotation_prefix) {
            packed_local_data.allocate(pb, 20 * BATCH, FMT(annotation_prefix, " packed local data"));
            this->update_all_vars();
        }

        std::shared_ptr <r1cs_pcd_local_data<FieldT>> get_local_data() const {
            ASSERT(false, "This class don't compute local data, compute it by yourself.");
            return nullptr;
        }

        ~zkspv_pcd_local_data_variable() = default;
    };

    template<typename FieldT>
    class zkspv_message_packer : public gadget<FieldT> {
    public:
        pb_variable_array <FieldT> repacked;
        size_t capacity;


        pb_variable_array <FieldT> fully_packed;
        pb_variable_array <FieldT> unpacked;

        std::shared_ptr <multipacking_gadget<FieldT>> unpacker;
        std::shared_ptr <multipacking_gadget<FieldT>> repacker;
    public:
        zkspv_message_packer(protoboard <FieldT> &pb,
                             pb_variable_array <FieldT> &fully_packed_in,
                             size_t capacity,
                             const std::string &annotation_prefix) :
                gadget<FieldT>(pb, annotation_prefix), capacity(capacity),
                fully_packed(fully_packed_in) {
            unpacked.allocate(pb, MSG_LEN, " unpacked message");
            repacked.allocate(pb, MSG_LEN / 32, " repacked message");
            unpacker.reset(new multipacking_gadget<FieldT>(pb, unpacked, fully_packed, capacity,
                                                           FMT(this->annotation_prefix, " message fully packer")));
            pb_variable_array <FieldT> unpacked_(unpacked);
            byteReverse(unpacked_, 32);
            byteReverse(unpacked_, 8);

            repacker.reset(new multipacking_gadget<FieldT>(pb, unpacked_, repacked, 32,
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

        void byteReverse(pb_variable_array <FieldT> &vch, size_t cell) {
            assert(vch.size() % cell == 0);
            typename pb_variable_array<FieldT>::iterator it;
            it = vch.begin();
            while (it != vch.end()) {
                std::reverse(it, it + cell);
                it += cell;
            }
            return;
        }
    };
}


#endif //BOOTCAMP_ZKPSPV_SPV_SPCP_HPP
