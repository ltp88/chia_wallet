//
//  wrapper.cpp
//  Runner
//
//  Created by Phuong Lam on 5/9/21.
//

#include <stdint.h>
#include "bls.hpp"

extern "C" __attribute__((visibility("default"))) __attribute__((used))
int32_t native_add(int32_t x, int32_t y) {
    return x + y;
};

extern "C" __attribute__((visibility("default"))) __attribute__((used))
uint8_t* gen() {
    std::vector<uint8_t> seed = {0,  50, 6,  244, 24,  199, 1,  25,  52,  88,  192,
                                19, 18, 12, 89,  6,   220, 18, 102, 58,  209, 82,
                                12, 62, 89, 110, 182, 9,   44, 20,  254, 22};

    bls::PrivateKey sk = bls::AugSchemeMPL().KeyGen(seed);
    bls::G1Element pk = sk.GetG1Element();
    return pk.Serialize().data();
}
