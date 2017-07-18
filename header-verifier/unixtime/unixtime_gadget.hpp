#ifndef UNIXTIME_GADGETS_HPP_
#define UNIXTIME_GADGETS_HPP_

#include <cassert>
#include <memory>

#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"

namespace libsnark {

template<typename FieldT>
class unixtime_gadget : public gadget<FieldT> {

private:
	
	std::shared_ptr<packing_gadget<FieldT> > b_unpacker;
	pb_variable_array<FieldT> b_bits;
	pb_linear_combination<FieldT> B;
	pb_variable<FieldT> les, leq;
	std::shared_ptr<comparison_gadget<FieldT> > cmp;

public:
	const pb_variable<FieldT> A;
	const pb_variable<FieldT> b;

	unixtime_gadget(protoboard<FieldT> &pb,
					const pb_variable<FieldT> &A,
					const pb_variable<FieldT> &b,
					const std::string &annotation_prefix="");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libsnark
#include "unixtime_gadget.tcc"

#endif // DIFFICULTY_COMPARISON_GADGETS_HPP_
