/**
 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <common/default_types/r1cs_ppzkpcd_pp.hpp>
#include <zk_proof_systems/pcd/r1cs_pcd/r1cs_sp_ppzkpcd/r1cs_sp_ppzkpcd.hpp>
#include "run_r1cs_sp_ppzkpcd.hpp"

using namespace libsnark;

template<typename PCD_ppT>
void profile_tally(size_t wordsize_, size_t arity_)
{
    const size_t wordsize = wordsize_;
    const size_t arity = arity_;
    const size_t max_layer = 0;
    const bool test_serialization = false;
    const bool bit = run_r1cs_sp_ppzkpcd_tally_example<PCD_ppT>(wordsize, arity, max_layer, test_serialization);
    assert(bit);
}

int main(void)
{
    typedef default_r1cs_ppzkpcd_pp PCD_pp;

    start_profiling();
    PCD_pp::init_public_params();


    size_t a[5] = {2,3,4,6,8};
    size_t b[5] = {16,24,32,48,64};

    for(int i=0;i<5;i++){
        for(int j=0;j<5;j++){
            profile_tally<PCD_pp>(b[j], a[j]);
        }
    }

    return 0;
}
