#ifndef MEDIAN11_GADGETS_TCC_
#define MEDIAN11_GADGETS_TCC_

#include<algorithm>

#include "common/profiling.hpp"
#include "common/utils.hpp"

namespace libsnark {

template<typename FieldT>
median11_gadget<FieldT>::median11_gadget(protoboard<FieldT> &pb,
					const pb_variable_array<FieldT> &inp,
					const pb_variable<FieldT> &res,
					const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix), inp(inp), res(res) {
	assert(inp.size() == 11);
	les.allocate(pb, 11, FMT(this->annotation_prefix, " les"));
	leq.allocate(pb, 11, FMT(this->annotation_prefix, " leq"));

	med.allocate(pb);

	l0.allocate(pb);
	l1.allocate(pb);
	le0.allocate(pb);
	le1.allocate(pb);
	
	for (int i = 0; i < 11; ++i) {
		cmps.emplace_back(comparison_gadget<FieldT>(this->pb, 32, med, inp[i], les[i], leq[i]));
	}

	//sum up les and leq
	linear_combination<FieldT> lsles, lsleq;
	for (int i = 0; i < 11; ++i) {
		lsles.add_term(les[i]);
		lsleq.add_term(leq[i]);
	}
	sles.assign(this->pb, lsles);
	sleq.assign(this->pb, lsleq);

	linear_combination<FieldT> six;
	six.add_term(ONE, FieldT(6));
	SIX.assign(this->pb, six);

	lcmp.reset(new comparison_gadget<FieldT>(this->pb, 4, sles, SIX, l0, le0));
	lecmp.reset(new comparison_gadget<FieldT>(this->pb, 4, SIX, sleq, l1, le1));
}

template<typename FieldT>
void median11_gadget<FieldT>::generate_r1cs_constraints() {
	//compare med with all numbers to get les and leq
	for (int i = 0; i < 11; ++i) {
		cmps[i].generate_r1cs_constraints();
	}
	//final cmp
	lcmp->generate_r1cs_constraints();
	lecmp->generate_r1cs_constraints();
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(l0, le1, 1));
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(med, 1, res));
}

template<typename FieldT>
void median11_gadget<FieldT>::generate_r1cs_witness() {
	std::vector<unsigned> nums;
	for (int i = 0; i < 11; ++i) {
		nums.push_back(this->pb.val(inp[i]).as_ulong());
	}
	std::nth_element(nums.begin(), nums.begin() + 5, nums.end());
	this->pb.val(med) = nums[5];
	for (int i = 0; i < 11; ++i) {
		cmps[i].generate_r1cs_witness();
	}
	lcmp->generate_r1cs_witness();
	lecmp->generate_r1cs_witness();
	this->pb.val(res) = this->pb.val(med);
}


} // libsnark
#endif // MEDIAN11_GADGETS_TCC_
