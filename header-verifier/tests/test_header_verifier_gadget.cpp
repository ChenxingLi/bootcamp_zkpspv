#include <cassert>
#include <cstdio>

#include "common/default_types/r1cs_ppzksnark_pp.hpp"
#include "common/profiling.hpp"
#include "common/utils.hpp"
#include "zk_proof_systems/ppzksnark/r1cs_ppzksnark/examples/run_r1cs_ppzksnark.hpp"
#include "gadgetlib1/gadgets/header_verifier/header_verifier_gadget.hpp"

const char* sample_headers[] = {
"100000204364c966fae5ae0242b13c17d92eb004b1d81f85d6f67d0000000000000000000309f0b9a2cff76e20de6cf71114ab3f6d061aaac1c501dc0d73abb3b38899fe9c1f6d59dc5d011826009752",
"10000020670b600f6deb63be236764dd013fdca071f2be230fb10d010000000000000000d77b83ae14bfe06f14bb01e5aaaa5f29679bc7cdbd93a3de62070cf8810dd6047f1c6d59dc5d011861176a68",
"1200002058104a90aa46e9a5df7bf27fc01d4792a492ca37448d1701000000000000000059b5192d270dab564aa69e594cd8d65b92e9b0bc59f83ab74b87ec73807d6c08f81b6d59dc5d011867a183e6",
"0200002070084eb0bd093765caf5f6936dfcad8eeafc46d4feeb900000000000000000002de29e9acf489478ec54a28ab65cd3fba82c4caaed9824000bd0021c69ffc3b6261a6d59dc5d01189f34fc8c",
"10000020cc44d7376bba4ae9f620c48b2e9c8a0e423b3a01a6883c0100000000000000004b1e86632bcf5604f768b69fb022018ed4a36bb2f778cc17efe9168c7ec0c28309176d59dc5d011881c7b354",
"02000020a00d7c5ffb992923d23ebd63d1928f50f301bc1912a03b01000000000000000031e6169e1f3c9817ea7523248b9ee869a32ee9b5d3f93f7169c333eb28b5fab40e156d59dc5d011812af9fc7",
"00000020357b7c8e86fd0b76c896cb6cb516417366913dcaec4410000000000000000000d9373372d530bb3c633796b050b7d376ba49525fcb4bb56af1b82fe1b8ccb835ff136d59dc5d0118fefbe125",
"10000020eda1fb44849d9a371bf345c4c0d98ef5f0064efe7610550000000000000000009fad331c30ac1a0639adf9ff78b953cc2f6e9956ef1d55570e6db879bac7e2fb7a136d59dc5d011897855309",
"100000202313f27b0b91489bcddca448b4c621a04366a45e3154bd0000000000000000008799e8b70cd66479f51cdc2e298fb01fc6408cd9cd6a6a90077b059da7f153821a116d59dc5d011830976782",
"020000208d0c715f0a32cca0f14a739114209fd90686dc481a2ece000000000000000000895fe03d7fa2b4cc8f8df0860396eb1ae6a4f8659cd5dacc1cfc4bd5d3b3cdf48c0f6d59dc5d01182189e871",
"100000207b1b2ffe46237e6b47ed1cb7ec6f8db59636f0aa29ed68000000000000000000a6bed612c04e53c779c143e6ae575c5aef888314ecec1774cfd4306c7d03d98ffe0d6d59dc5d0118c927ef24",
"1000002079e410094c42c45558c31dd42538d7b4e89930a97b4f30000000000000000000488ffe595e9653a94089ebac0599067e152e352f8e953ae1412b22af0c0630c1670d6d59dc5d01185cbab1bb",
"02000020429dade771acb5b43931e6e4ec52f741635ef388710ce00000000000000000008b085ae1d2cf84cfa84489b01a268b52a20ae047ec6bbd3a2f1740ccd5df409ccc0c6d59dc5d011826fac0b5",
"100000201ab196dd0d551a9637d80f87f171c9bf03041075530c26010000000000000000d85b8394968d95d0fae1cd6a6d22b74546d8a40c84190053f4e7398b92b937027b0c6d59dc5d011853a99244",
"120000200dba793c1ead8b52c1547713e3ee71c95280e84bc531a10000000000000000000c3a3d6a3ea5da22b89e47f63421fa41119e6303760c5c6fce3c6afb434a40d6f30a6d59dc5d0118605264c4"
};

const size_t MSG_SIZE = 8 + 11 + 8 + 1,
			 LOCAL_SIZE = 20;

unsigned get_unsigned(const char *s, bool reversed = false) {
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
		if (!reversed) {
			ret = ret << 4 | bit4;
		} else {
			int exp = (i / 2) * 8 + (1 - i % 2) * 4;
			ret = ret | (bit4 << exp);
		}
	}
	return ret;
}

namespace libsnark {
	template<typename FieldT>
	r1cs_example<FieldT> gen_r1cs_header_verifier_example(int thisBlock = 0)
	{
		protoboard<FieldT> pb;

		pb_variable_array<FieldT> msg_input, local_input, msg_output;

		msg_input.allocate(pb, MSG_SIZE, "msg_input");
		local_input.allocate(pb, LOCAL_SIZE, "local_input");
		msg_output.allocate(pb, MSG_SIZE, "msg_output");

		header_verifier_gadget<FieldT> header_verifier(pb, msg_input, local_input, msg_output, "header_verifier");

		header_verifier.generate_r1cs_constraints();

		for (int i = 0; i < 20; ++i) {
			pb.val(local_input[i]) = get_unsigned(sample_headers[thisBlock] + i * 8);
		}

		for (int i = 0; i < 8; ++i) {
			pb.val(msg_input[i]) = get_unsigned(sample_headers[thisBlock] + 8 + i * 8);
		}

		for (int i = 0; i < 11; ++i) {
			pb.val(msg_input[8 + i]) = get_unsigned(sample_headers[thisBlock + 1 + i] + 136, true);
		}

		header_verifier.generate_r1cs_witness();
		return r1cs_example<FieldT>(pb.get_constraint_system(), pb.primary_input(), pb.auxiliary_input());
	}
};

using namespace libsnark;

int main(int argc, const char * argv[])
{
    default_r1cs_ppzksnark_pp::init_public_params();
    start_profiling();

    enter_block("Generate R1CS example");
    r1cs_example<Fr<default_r1cs_ppzksnark_pp> > example = gen_r1cs_header_verifier_example<Fr<default_r1cs_ppzksnark_pp> >();
    leave_block("Generate R1CS example");

    print_header("(enter) Profile R1CS ppzkSNARK");
    const bool test_serialization = true;
    run_r1cs_ppzksnark<default_r1cs_ppzksnark_pp>(example, test_serialization);
    print_header("(leave) Profile R1CS ppzkSNARK");
}
