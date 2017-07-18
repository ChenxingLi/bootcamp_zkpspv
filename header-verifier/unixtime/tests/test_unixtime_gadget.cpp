#include <cassert>
#include <cstdio>

#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp"
#include "gadgetlib1/gadgets/header_verifier/unixtime/unixtime_gadget.hpp"

unsigned get_unsigned(const char *s) {
	//edian checked!
	unsigned ret = 0;
	for (int i = 0; i < 8; ++i) {
		char d = *(s + i);
		unsigned bit4 = 0;
		if (d >= 'a' && d <= 'f') {
			bit4 = 10 + d - 'a';
		} else {
			bit4 = d - '0';
		}
		ret = ret << 4 | bit4;
	}
	return ret;
}

namespace libsnark {
	template<typename FieldT>
	r1cs_example<FieldT> gen_r1cs_unixtime_example()
	{
		protoboard<FieldT> pb;

		pb_variable<FieldT> a, b;

		a.allocate(pb);
		b.allocate(pb);

		unixtime_gadget<FieldT> tcmp(pb, a, b, "unixtime_cmp");
		printf("construction\n");

		tcmp.generate_r1cs_constraints();
		printf("generate constraints\n");

		pb.val(a) = get_unsigned("495FAB29");
		pb.val(b) = get_unsigned("24d95a54");
		
		/*
		pb.val(b) = get_unsigned("495FAB23");
		pb.val(a) = get_unsigned("24d95a54");
		*/

		tcmp.generate_r1cs_witness();
		printf("generate witnesses\n");

		return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
	}
};

using namespace libsnark;

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    start_profiling();

    enter_block("Generate R1CS example");
    r1cs_example<Fr<default_r1cs_ppzksnark_pp> > example = gen_r1cs_unixtime_example<Fr<default_r1cs_ppzksnark_pp> >();
    leave_block("Generate R1CS example");

    print_header("(enter) Profile R1CS ppzkSNARK");
    const bool test_serialization = true;
    run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example, test_serialization);
    print_header("(leave) Profile R1CS ppzkSNARK");
}
