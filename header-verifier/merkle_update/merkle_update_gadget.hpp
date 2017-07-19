#ifndef MARKLE_UPDATE_GADGETS_HPP_
#define MARKLE_UPDATE_GADGETS_HPP_

#include <cassert>
#include <memory>

#include "gadgetlib1/gadget.hpp"
#include "gadgetlib1/gadgets/basic_gadgets.hpp"
#include "gadgetlib1/gadgets/merkle_tree/merkle_tree_check_update_gadget.hpp"

namespace libsnark {

template<typename FieldT, typename HashT>
class merkle_update_gadget : public gadget<FieldT> {

private:
	std::shared_ptr<digest_variable<FieldT> > v1, v2;	
	std::shared_ptr<merkle_authentication_path_variable<FieldT, HashT> > p1, p2;
	std::shared_ptr<merkle_tree_check_update_gadget<FieldT, HashT> > checker;
	pb_linear_combination<FieldT> succ;

	pb_variable<FieldT> a1p, a2p;
	std::shared_ptr<packing_gadget<FieldT> > a2per;

	std::vector<packing_gadget<FieldT> > bp;
	std::vector<pb_variable_array<FieldT> > bbits;

	std::shared_ptr<HashT> CRH;


public:

	pb_variable_array<FieldT> a2, r2a;
	std::shared_ptr<digest_variable<FieldT> > r1, r2;
	pb_variable_array<FieldT> b;

	merkle_update_gadget(protoboard<FieldT> &pb,
			const pb_variable<FieldT> &a1p,
			const pb_variable<FieldT> &a2p,
			const pb_variable_array<FieldT> &r1a,
			const pb_variable_array<FieldT> &r2a,
			const pb_variable_array<FieldT> &b,
			const std::string &annotation_prefix="");

	void generate_r1cs_constraints();
	void generate_r1cs_witness();
};

} // libsnark
#include "merkle_update_gadget.tcc"

#endif // MARKLE_UPDATE_GADGETS_HPP_
