#ifndef DIFFICULTY_COMPARISON_GADGETS_TCC_
#define DIFFICULTY_COMPARISON_GADGETS_TCC_

#include<algorithm>

#include "common/profiling.hpp"
#include "common/utils.hpp"

namespace libsnark {

template<typename FieldT>
difficulty_comparison_gadget<FieldT>::difficulty_comparison_gadget(protoboard<FieldT> &pb,
					const pb_variable_array<FieldT> &hash,
					const pb_variable<FieldT> &nbits,
					const std::string &annotation_prefix) : gadget<FieldT>(pb, annotation_prefix), hash(hash), nbits(nbits) {
	nbits_bits.allocate(pb, 33);

	linear_combination<FieldT> tnbits;
	tnbits.add_term(nbits);
	tnbits.add_term(ONE, (FieldT(2) ^ 32) - 3);
	pb_linear_combination<FieldT> snbits;
	snbits.assign(pb, tnbits);

	nbits_unpacker.reset(new packing_gadget<FieldT>(pb, nbits_bits, snbits));
	linear_combination<FieldT> tlow;
	for (int i = 0; i < 7; ++i) {
		hash_bits.emplace_back(pb_variable_array<FieldT>());
		hash_bits.back().allocate(pb, 32);
		hash_unpacker.emplace_back(packing_gadget<FieldT>(pb, hash_bits[i], hash[i]));
		for (int j = 0, cnt = 0; j < 4; ++j) {
			for (int k = 7; k >= 0; --k) {
				tlow.add_term(hash_bits[i][31 - j * 8 - k], FieldT(2) ^ (32 * i + cnt++));
			}
		}
	}
	low_hash.assign(pb, tlow);

	nbits_exp.allocate(pb, 8);
	muls.allocate(pb, 8);

	linear_combination<FieldT> tsig;
	for (int i = 0, cnt = 0; i < 3; ++i) {
		for (int j = 7; j >= 0; --j) {
			tsig.add_term(nbits_bits[31 - i * 8 - j], FieldT(2) ^ (cnt++));
		}
	}
	signif.assign(pb, tsig);

	linear_combination<FieldT> texp;
	for (int i = 0; i < 8; ++i) {
		texp.add_term(nbits_bits[i], FieldT(2) ^ i);
	}
	exp.assign(pb, texp);

	linear_combination<FieldT> t26;
	t26.add_term(ONE, 26);
	TWENTYSIX.assign(pb, t26);

	eles.allocate(pb);
	eleq.allocate(pb);
	exp_cmp.reset(new comparison_gadget<FieldT>(pb, 8, exp, TWENTYSIX, eles, eleq));

	difficulty.allocate(pb);	
	les.allocate(pb);
	leq.allocate(pb);
	cmp.reset(new comparison_gadget<FieldT>(pb, 256 - 32, low_hash, difficulty, les, leq));
}

template<typename FieldT>
void difficulty_comparison_gadget<FieldT>::generate_r1cs_constraints() {
	nbits_unpacker->generate_r1cs_constraints(true);
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, nbits_bits[32], 1));
	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, hash[7], 0));
	for (int i = 0; i < 7; ++i) {
		hash_unpacker[i].generate_r1cs_constraints(true);
	}

	for (int i = 0; i < 8; ++i) {
		this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(nbits_bits[i], (FieldT(256) ^ (1 << i)) - 1, nbits_exp[i] - 1));
		if (!i) {
			this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(nbits_exp[i], 1, muls[i]));
		} else {
			this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(nbits_exp[i], muls[i - 1], muls[i]));
		}
	}

	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(muls[7], signif, difficulty));

	exp_cmp->generate_r1cs_constraints();

	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(eleq, 1, 1));

	cmp->generate_r1cs_constraints();

	this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(les, 1, 1));
}

template<typename FieldT>
void difficulty_comparison_gadget<FieldT>::generate_r1cs_witness() {
	nbits_unpacker->generate_r1cs_witness_from_packed();
	for (int i = 0; i < 7; ++i) {
		hash_unpacker[i].generate_r1cs_witness_from_packed();
	}
	signif.evaluate(this->pb);
	for (int i = 0; i < 8; ++i) {
		if ((this->pb.val(nbits_bits[i])).as_ulong() == 1) {
			//printf("1");
			this->pb.val(nbits_exp[i]) = FieldT(256) ^ (1 << i);
		} else {
			//printf("0");
			this->pb.val(nbits_exp[i]) = FieldT(1);
		}
		if (!i) {
			this->pb.val(muls[i]) = this->pb.val(nbits_exp[i]);
		} else {
			this->pb.val(muls[i]) = this->pb.val(nbits_exp[i]) * this->pb.val(muls[i - 1]);
		}
	}
	this->pb.val(difficulty) = this->pb.val(muls[7]) * (this->pb.lc_val(signif));

	low_hash.evaluate(this->pb);

	exp_cmp->generate_r1cs_witness();
	cmp->generate_r1cs_witness();

}

} // libsnark
#endif // DIFFICULTY_COMPARISON_GADGETS_TCC_
