/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <libsnark/common/default_types/r1cs_ppzkpcd_pp.hpp>
#include <libsnark/zk_proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>
#include "run_r1cs_sp_ppzkpcd.hpp"

using namespace libsnark;

template<typename PCD_ppT>
void profile_tally(size_t wordsize_, size_t csize_, size_t max_layer_)
{
    const size_t wordsize = wordsize_;
    const size_t arity = 1;
    const size_t csize = csize_;
    const size_t max_layer = max_layer_;
    const bool test_serialization = false;
    const bool bit = run_r1cs_sp_ppzkpcd_tally_example<PCD_ppT>(wordsize, arity, max_layer, csize, test_serialization);
    assert(bit);
}

int main(int argc, char* argv[])
{
    typedef default_r1cs_ppzkpcd_pp PCD_pp;

    libff::start_profiling();
    PCD_pp::init_public_params();

    profile_tally<PCD_pp>(atoi(argv[1]), atoi(argv[2]), atoi(argv[3]));

    return 0;
}
