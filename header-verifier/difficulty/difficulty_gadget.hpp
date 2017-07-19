#ifndef DIFFICULTY_COMPARISON_GADGETS_HPP_
#define DIFFICULTY_COMPARISON_GADGETS_HPP_

#include <cassert>
#include <memory>

#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"

namespace libsnark {

template<typename FieldT>
class difficulty_comparison_gadget : public gadget<FieldT> {

private:
	std::shared_ptr<packing_gadget<FieldT> > nbits_unpacker;
	pb_variable_array<FieldT> nbits_bits, nbits_exp, muls;
	std::vector<packing_gadget<FieldT> > hash_unpacker;
	std::vector<pb_variable_array<FieldT> > hash_bits;
	pb_linear_combination<FieldT> low_hash, exp, signif, TWENTYSIX;
	pb_variable<FieldT> difficulty;
	std::shared_ptr<comparison_gadget<FieldT> > cmp, exp_cmp;
	pb_variable<FieldT> les, leq, eles, eleq;

public:
	const pb_variable_array<FieldT> hash;
	const pb_variable<FieldT> nbits;

	difficulty_comparison_gadget(protoboard<FieldT> &pb,
					const pb_variable_array<FieldT> &hash,
					const pb_variable<FieldT> &nbits,
					const std::string &annotation_prefix="");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libsnark
#include "difficulty_gadget.tcc"

#endif // DIFFICULTY_COMPARISON_GADGETS_HPP_
