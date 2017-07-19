#ifndef UNIXTIME_GADGETS_TCC_
#define UNIXITME_GADGETS_TCC_

#include<algorithm>

#include "common/profiling.hpp"
#include "common/utils.hpp"

namespace libsnark {

template<typename FieldT>
unixtime_gadget<FieldT>::unixtime_gadget(protoboard<FieldT> &pb,
					const pb_variable<FieldT> &A,
					const pb_variable<FieldT> &b,
					const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix), A(A), b(b) {
	b_bits.allocate(pb, 32);
	b_unpacker.reset(new packing_gadget<FieldT>(pb, b_bits, b));
	
	linear_combination<FieldT> tb;
	for (int i = 3, cnt = 0; i >= 0; --i) {
		for (int j = 0; j < 8; ++j) {
			tb.add_term(b_bits[i * 8 + j], FieldT(2) ^ (cnt++));
		}
	}
	B.assign(pb, tb);

	les.allocate(pb);
	leq.allocate(pb);
	cmp.reset(new comparison_gadget<FieldT>(pb, 32, A, B, les, leq));
}

template<typename FieldT>
void unixtime_gadget<FieldT>::generate_r1cs_constraints() {
	b_unpacker->generate_r1cs_constraints(true);
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(b_bits[7], 1, 0));
	cmp->generate_r1cs_constraints();
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(les, 1, 1));
}

template<typename FieldT>
void unixtime_gadget<FieldT>::generate_r1cs_witness() {
	b_unpacker->generate_r1cs_witness_from_packed();
	cmp->generate_r1cs_witness();
}

} // libsnark
#endif // UNIXTIME_COMPARISON_GADGETS_TCC_
