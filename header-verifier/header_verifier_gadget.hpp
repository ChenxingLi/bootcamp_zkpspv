#ifndef HEADER_VERIFIER_GADGETS_HPP_
#define HEADER_VERIFIER_GADGETS_HPP_

#include <cassert>
#include <memory>

#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "gadgetlib1/gadgets/header_verifier/median11/median11_gadget.hpp"
#include "gadgetlib1/gadgets/header_verifier/unixtime/unixtime_gadget.hpp"
#include "gadgetlib1/gadgets/header_verifier/difficulty/difficulty_gadget.hpp"
//#include "gadgetlib1/gadgets/header_verifier/SHA256/SHA256x2_gadget.hpp"

namespace libsnark {

template<typename FieldT>
class header_verifier_gadget : public gadget<FieldT> {

private:
	pb_variable<FieldT> timestamp_median;
	std::shared_ptr<median11_gadget<FieldT> > median11;
	std::shared_ptr<unixtime_gadget<FieldT> > timecmp;
	//std::shard_ptr<SHA256x2_gadget<FieldT> > SHA256x2;
	pb_variable_array<FieldT> this_hash;
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
#include "header_verifier/header_verifier_gadget.tcc"

#endif // HEADER_VERIFIER_GADGETS_HPP_
