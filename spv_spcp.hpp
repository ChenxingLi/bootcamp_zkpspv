//
// Created by lylcx-mac on 2017/7/17.
//

#ifndef BOOTCAMP_ZKPSPV_SPV_SPCP_HPP
#define BOOTCAMP_ZKPSPV_SPV_SPCP_HPP

#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp"
#include "tool.h"
#include <vector>

namespace libsnark {
    template <typename FieldT>
    class zkspv_pcd_message : public r1cs_pcd_message<FieldT> {
    public:
        std::vector<char> unpacked_data;

        uint256 hash;

        zkspv_pcd_message(const size_t type, uint256 hash): r1cs_pcd_message<FieldT>(type), hash(hash){
            unpacked_data.insert(unpacked_data.end(), hash.begin(),hash.end());
        }
        r1cs_variable_assignment<FieldT> payload_as_r1cs_variable_assignment() const {

        }
        void print() const;

        ~tally_pcd_message() = default;
    };
}




#endif //BOOTCAMP_ZKPSPV_SPV_SPCP_HPP
