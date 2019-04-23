/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.mtwilson.core.tpm.util;

import com.intel.mtwilson.core.tpm.Tpm;
import tss.tpm.TPMA_NV;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class NvAttributeMapper {
    public static TPMA_NV getMappedNvAttribute(Tpm.NVAttribute attr) {
        TPMA_NV._N tpmNvAttribute = TPMA_NV._N.valueOf(attr.name());
        TPMA_NV nvAttribute;
        switch (tpmNvAttribute) {
            case PPWRITE :
                nvAttribute = TPMA_NV.PPWRITE;
                break;
            case OWNERWRITE :
                nvAttribute = TPMA_NV.OWNERWRITE;
                break;
            case AUTHWRITE :
                nvAttribute = TPMA_NV.AUTHWRITE;
                break;
            case POLICYWRITE :
                nvAttribute = TPMA_NV.POLICYWRITE;
                break;
            case ORDINARY :
                nvAttribute = TPMA_NV.ORDINARY;
                break;
            case COUNTER :
                nvAttribute = TPMA_NV.COUNTER;
                break;
            case BITS :
                nvAttribute = TPMA_NV.BITS;
                break;
            case EXTEND :
                nvAttribute = TPMA_NV.EXTEND;
                break;
            case PIN_FAIL :
                nvAttribute = TPMA_NV.PIN_FAIL;
                break;
            case PIN_PASS :
                nvAttribute = TPMA_NV.PIN_PASS;
                break;
            case TpmNt_BIT_0 :
                nvAttribute = TPMA_NV.TpmNt_BIT_0;
                break;
            case TpmNt_BIT_1 :
                nvAttribute = TPMA_NV.TpmNt_BIT_1;
                break;
            case TpmNt_BIT_2 :
                nvAttribute = TPMA_NV.TpmNt_BIT_2;
                break;
            case TpmNt_BIT_3 :
                nvAttribute = TPMA_NV.TpmNt_BIT_3;
                break;
            case POLICY_DELETE :
                nvAttribute = TPMA_NV.POLICY_DELETE;
                break;
            case WRITELOCKED :
                nvAttribute = TPMA_NV.WRITELOCKED;
                break;
            case WRITEALL :
                nvAttribute = TPMA_NV.WRITEALL;
                break;
            case WRITEDEFINE :
                nvAttribute = TPMA_NV.WRITEDEFINE;
                break;
            case WRITE_STCLEAR :
                nvAttribute = TPMA_NV.WRITE_STCLEAR;
                break;
            case GLOBALLOCK :
                nvAttribute = TPMA_NV.GLOBALLOCK;
                break;
            case PPREAD :
                nvAttribute = TPMA_NV.PPREAD;
                break;
            case OWNERREAD :
                nvAttribute = TPMA_NV.OWNERREAD;
                break;
            case AUTHREAD :
                nvAttribute = TPMA_NV.AUTHREAD;
                break;
            case POLICYREAD :
                nvAttribute = TPMA_NV.POLICYREAD;
                break;
            case NO_DA :
                nvAttribute = TPMA_NV.NO_DA;
                break;
            case ORDERLY :
                nvAttribute = TPMA_NV.ORDERLY;
                break;
            case CLEAR_STCLEAR :
                nvAttribute = TPMA_NV.CLEAR_STCLEAR;
                break;
            case READLOCKED :
                nvAttribute = TPMA_NV.READLOCKED;
                break;
            case WRITTEN :
                nvAttribute = TPMA_NV.WRITTEN;
                break;
            case PLATFORMCREATE :
                nvAttribute = TPMA_NV.PLATFORMCREATE;
                break;
            case READ_STCLEAR :
                nvAttribute = TPMA_NV.READ_STCLEAR;
                break;
            default:
                throw new RuntimeException("Invalid policy defined for NV Index");
        }
        return nvAttribute;
    }

    public static TPMA_NV getTpmaNvFromAttributes(Set<Tpm.NVAttribute> attributes) {
        List<TPMA_NV> nvAttributeList = new ArrayList<>();
        for(Tpm.NVAttribute attr : attributes) {
            nvAttributeList.add(NvAttributeMapper.getMappedNvAttribute(attr));
        }
        return new TPMA_NV(nvAttributeList.toArray(new TPMA_NV[nvAttributeList.size()]));
    }

}
