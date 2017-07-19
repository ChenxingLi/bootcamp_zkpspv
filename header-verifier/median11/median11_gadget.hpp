#ifndef MEDIAN11_GADGETS_HPP_
#define MEDIAN11_GADGETS_HPP_

#include <cassert>
#include <memory>

#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"

namespace libsnark {

template<typename FieldT>
class median11_gadget : public gadget<FieldT> {

private:
	pb_variable_array<FieldT> les, leq;
	pb_variable<FieldT> med;
	std::vector<comparison_gadget<FieldT> > cmps;
	pb_linear_combination<FieldT> sles, sleq, SIX;
	std::shared_ptr<comparison_gadget<FieldT> > lcmp, lecmp;
	pb_variable<FieldT> l0, l1, le0, le1;

public:
	const pb_variable_array<FieldT> inp;
	const pb_variable<FieldT> res;

	median11_gadget(protoboard<FieldT> &pb,
					const pb_variable_array<FieldT> &inp,
					const pb_variable<FieldT> &res,
					const std::string &annotation_prefix="");

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

} // libsnark
#include "median11_gadget.tcc"

#endif // MEDIAN11_GADGETS_HPP_
