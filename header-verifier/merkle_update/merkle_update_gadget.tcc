#ifndef MERKLE_UPDATE_GADGETS_TCC_
#define MERKLE_UPDATE_GADGETS_TCC_

#include<algorithm>

#include "common/profiling.hpp"
#include "common/utils.hpp"

namespace libsnark {

	/*
	merkle_tree_check_update_gadget(protoboard<FieldT> &pb,
			const size_t tree_depth,
			const pb_variable_array<FieldT> &address_bits,
			const digest_variable<FieldT> &prev_leaf_digest,
			const digest_variable<FieldT> &prev_root_digest,
			const merkle_authentication_path_variable<FieldT, HashT> &prev_path,
			const digest_variable<FieldT> &next_leaf_digest,
			const digest_variable<FieldT> &next_root_digest,
			const merkle_authentication_path_variable<FieldT, HashT> &next_path,
			const pb_linear_combination<FieldT> &update_successful,
			const std::string &annotation_prefix);
	*/


	template<typename FieldT, typename HashT>
	merkle_update_gadget<FieldT, HashT>::merkle_update_gadget(protoboard<FieldT> &pb,
				const pb_variable<FieldT> &a1p,
				const pb_variable<FieldT> &a2p,
				const pb_variable_array<FieldT> &r1a,
				const pb_variable_array<FieldT> &r2a,
				const pb_variable_array<FieldT> &b,
				const std::string &annotation_prefix) :
			gadget<FieldT>(pb, annotation_prefix),
			a1p(a1p),
			a2p(a2p),
			r2a(r2a),
			b(b) {


	this->a1p.allocate(pb);
	this->a2p.allocate(pb);
	a2.allocate(pb, 32);
	a2per.reset(new packing_gadget<FieldT>(pb, a2, a2p));
	for (int i = 0; i < 20; ++i) {
		bbits.emplace_back(pb_variable_array<FieldT>());
		bbits[i].allocate(pb, 32);
		bp.emplace_back(packing_gadget<FieldT>(pb, bbits[i], b[i]));
	}
	block_variable<FieldT> bblock(pb, bbits, "");

	v2.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), ""));	
	CRH.reset(new HashT(pb, 640, bblock, *v2, ""));
	
	v1.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), ""));	
	r1.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), ""));	
	r2.reset(new digest_variable<FieldT>(pb, HashT::get_digest_len(), ""));	
	p1.reset(new merkle_authentication_path_variable<FieldT, HashT>(pb, 32, ""));
	p2.reset(new merkle_authentication_path_variable<FieldT, HashT>(pb, 32, ""));

	linear_combination<FieldT> tsucc;
	succ.assign(pb, tsucc);
	checker.reset(new merkle_tree_check_update_gadget<FieldT, HashT>(pb, 32, a2, *v1, *r1, *p1, *v2, *r2, *p2, succ, FMT(annotation_prefix, " checker")));
}

template<typename FieldT, typename HashT>
void merkle_update_gadget<FieldT, HashT>::generate_r1cs_constraints() {
	a2per->generate_r1cs_constraints(true);
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(a1p + 1, 0, a2p));
	for (int i = 0; i < 20; ++i) {
		bp[i].generate_r1cs_constraints(true);
	}
	CRH->generate_r1cs_constraints();
	checker->generate_r1cs_constraints();
}

template<typename FieldT, typename HashT>
void merkle_update_gadget<FieldT, HashT>::generate_r1cs_witness() {
	this->pb.val(a2p) = 0; //this->pb.val(a1p) + 1;
	a2per->generate_r1cs_witness_from_packed();
	for (int i = 0; i < 20; ++i) {
		bp[i].generate_r1cs_witness_from_packed();
	}
	//get P and P' from nowhere
	CRH->generate_r1cs_witness();
	//again we get v1 from nowhere
	//yet again we get r2 from nowhere
	checker->generate_r1cs_witness();
	for (int i = 0; i < 8; ++i) {
		this->pb.val(r2a[i]) = 0;
	}
}

} // libsnark
#endif // MERKLE_UPDATE_GADGETS_TCC_
