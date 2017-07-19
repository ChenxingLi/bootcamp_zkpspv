#include <cassert>
#include <cstdio>

#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp"
#include "gadgetlib1/gadgets/hashes/crh_gadget.hpp"
#include "gadgetlib1/gadgets/header_verifier/merkle_update/merkle_update_gadget.hpp"

namespace libsnark {
	template<typename FieldT>
	r1cs_example<FieldT> gen_r1cs_merkle_update_example()
	{
		protoboard<FieldT> pb;

		pb_variable<FieldT> a1, a2;

		a1.allocate(pb);
		a2.allocate(pb);

		pb_variable_array<FieldT> r1, r2;
		r1.allocate(pb, 8);
		r2.allocate(pb, 8);
		
		std::cout << CRH_with_bit_out_gadget<FieldT>::get_digest_len() << std::endl;

		pb_variable_array<FieldT> b;

		b.allocate(pb, 20);

		merkle_update_gadget<FieldT, CRH_with_bit_out_gadget<FieldT> > upd(pb, a1, a2, r1, r2, b, "merkle_update");
		printf("construction\n");

		upd.generate_r1cs_constraints();
		printf("generate constraints\n");

		upd.generate_r1cs_witness();
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
    r1cs_example<Fr<default_r1cs_ppzksnark_pp> > example = gen_r1cs_merkle_update_example<Fr<default_r1cs_ppzksnark_pp> >();
    leave_block("Generate R1CS example");

    print_header("(enter) Profile R1CS ppzkSNARK");
    const bool test_serialization = true;
    run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example, test_serialization);
    print_header("(leave) Profile R1CS ppzkSNARK");
}
