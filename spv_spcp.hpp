//
// Created by lylcx-mac on 2017/7/17.
//

#ifndef BOOTCAMP_ZKPSPV_SPV_SPCP_HPP
#define BOOTCAMP_ZKPSPV_SPV_SPCP_HPP

#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/compliance_predicate.hpp"
#include "zk_proof_systems/pcd/r1cs_pcd/compliance_predicate/cp_handler.hpp"

namespace libsnark {
    template <typename FieldT>
    class zkspv_pcd_message : public r1cs_pcd_message<FieldT> {
    public:
        size_t wordsize;

        size_t sum;
        size_t count;


        zkspv_pcd_message(const size_t type,
                          const size_t wordsize,
                          const size_t sum,
                          const size_t count);
        r1cs_variable_assignment<FieldT> payload_as_r1cs_variable_assignment() const;
        void print() const;

        ~tally_pcd_message() = default;
    };
}




#endif //BOOTCAMP_ZKPSPV_SPV_SPCP_HPP
