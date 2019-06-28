/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.util;

import com.intel.mtwilson.core.tpm.Tpm;
import tss.tpm.TPM_ALG_ID;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class PcrBanksMapper {
    public static List<TPM_ALG_ID> getMappedPcrBanks(Set<Tpm.PcrBank> pcrBanks) {
        List<TPM_ALG_ID> supportedBanks = new ArrayList<>();
        for(Tpm.PcrBank pb: pcrBanks) {
            switch(pb) {
                case SHA1:
                    supportedBanks.add(TPM_ALG_ID.SHA1);
                    break;
                case SHA256:
                    supportedBanks.add(TPM_ALG_ID.SHA256);
                    break;
                case SHA384:
                    supportedBanks.add(TPM_ALG_ID.SHA384);
                    break;
                case SHA512:
                    supportedBanks.add(TPM_ALG_ID.SHA512);
                    break;
                case SM3_256:
                    supportedBanks.add(TPM_ALG_ID.SM3_256);
                    break;
                default:
                    throw new RuntimeException("PCR Bank not supported yet");
            }
        }
        return supportedBanks;
    }
}
