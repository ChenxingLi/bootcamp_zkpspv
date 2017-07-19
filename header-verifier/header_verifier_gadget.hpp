#ifndef HEADER_VERIFIER_GADGETS_HPP_
#define HEADER_VERIFIER_GADGETS_HPP_

#include <cassert>
#include <memory>

#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "gadgetlib1/gadgets/hashes/crh_gadget.hpp"
#include "median11/median11_gadget.hpp"
#include "unixtime/unixtime_gadget.hpp"
#include "difficulty/difficulty_gadget.hpp"
#include "sha256_2/sha256_2_gadget.hpp"
#include "merkle_update/merkle_update_gadget.hpp"

namespace libsnark {

template<typename FieldT>
class header_verifier_gadget : public gadget<FieldT> {

private:
	pb_variable<FieldT> timestamp_median, this_addr;
	std::shared_ptr<median11_gadget<FieldT> > median11;
	std::shared_ptr<unixtime_gadget<FieldT> > timecmp;
	std::shared_ptr<sha256_2_function_check_gadget<FieldT> > SHA256x2;
	std::shared_ptr<merkle_update_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> > > merkle;
	pb_variable_array<FieldT> this_hash, this_root;
	std::shared_ptr<difficulty_comparison_gadget<FieldT> > diffcmp;

public:
	
	pb_variable_array<FieldT> msg_input, local_input, msg_output;

	header_verifier_gadget<FieldT>(protoboard<FieldT> &pb,
					const pb_variable_array<FieldT> &msg_input,
					const pb_variable_array<FieldT> &local_input,
					const pb_variable_array<FieldT> &msg_output,
					const std::string &annotation_prefix="");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libsnark
#include "header_verifier_gadget.tcc"

#endif // HEADER_VERIFIER_GADGETS_HPP_
