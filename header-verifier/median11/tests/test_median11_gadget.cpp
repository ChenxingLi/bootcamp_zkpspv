#include <cassert>
#include <cstdio>

#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "gadgetlib1/gadgets/header_verifier/median11/median11_gadget.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp"

namespace libsnark {
	template<typename FieldT>
	r1cs_example<FieldT> gen_r1cs_median_example()
	{
		const int num_inputs = 11;

		protoboard<FieldT> pb;
		pb_variable_array<FieldT> inp;
		pb_variable<FieldT> res;

		res.allocate(pb, "res");
		inp.allocate(pb, num_inputs, "inp");

		median11_gadget<FieldT> compute_median(pb, inp, res, "compute_median");
		compute_median.generate_r1cs_constraints();

		const int ub = 100;

		for (int i = 0; i < num_inputs; ++i) {
			int num = rand() % ub;
			printf("%d\n", num);
			pb.val(inp[i]) = FieldT(num);
		}

		compute_median.generate_r1cs_witness();
		return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
	}
};

using namespace libsnark;

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    start_profiling();

    enter_block("Generate R1CS example");
    r1cs_example<Fr<default_r1cs_ppzksnark_pp> > example = gen_r1cs_median_example<Fr<default_r1cs_ppzksnark_pp> >();
    leave_block("Generate R1CS example");

    print_header("(enter) Profile R1CS ppzkSNARK");
    const bool test_serialization = true;
    run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example, test_serialization);
    print_header("(leave) Profile R1CS ppzkSNARK");
}
