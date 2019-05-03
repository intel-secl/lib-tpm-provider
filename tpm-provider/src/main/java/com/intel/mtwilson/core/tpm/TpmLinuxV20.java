/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import gov.niarl.his.privacyca.TpmUtils;
import tss.TpmDeviceBase;
import java.io.IOException;
import java.util.Arrays;

/**
 *
 * @author dczech
 */
class TpmLinuxV20 extends TpmV20 {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmLinuxV20.class);

    TpmLinuxV20(TpmDeviceBase base) {
        super(base);
    }

    @Override
    public void setCredential(byte[] ownerAuth, Tpm.CredentialType credentialType, byte[] credentialBlob) throws IOException, Tpm.TpmException {
        if(credentialType != Tpm.CredentialType.EC) {
            throw new UnsupportedOperationException("Only CredentialType.EC is supported");
        }
        if(nvIndexExists(getECIndex())) {
            nvRelease(ownerAuth, getECIndex());
        }
        if(nvIndexExists(getECIndex()+1)) {
            nvRelease(ownerAuth, getECIndex() + 1);
        }
        if(credentialBlob == null) {
            return;
        }
        int part1 = credentialBlob.length/2;
        int part2 = credentialBlob.length - part1;
        nvDefine(ownerAuth, ownerAuth, getECIndex(), part1, Tpm.NVAttribute.AUTHWRITE, Tpm.NVAttribute.AUTHREAD);
        byte[] part1Buf = Arrays.copyOfRange(credentialBlob, 0, part1);
        byte[] part2Buf = Arrays.copyOfRange(credentialBlob, part1, credentialBlob.length);
        nvWrite(ownerAuth, getECIndex(), part1Buf);
        nvDefine(ownerAuth, ownerAuth, getECIndex() + 1, part2, Tpm.NVAttribute.AUTHWRITE, Tpm.NVAttribute.AUTHREAD);
        nvWrite(ownerAuth, getECIndex()+1, part2Buf);
    }

    @Override
    public byte[] getCredential(byte[] ownerAuth, Tpm.CredentialType credentialType) throws Tpm.TpmException, IOException {
        if (credentialType != Tpm.CredentialType.EC) {
            throw new UnsupportedOperationException("Credential Types other than EC (Endorsement Credential) are not yet supported");
        }
        if(nvIndexExists(getECIndex()) && nvIndexExists(getECIndex()+1)) {
            byte[] part1 = nvRead(ownerAuth, getECIndex(), nvIndexSize(getECIndex()));
            byte[] part2 = nvRead(ownerAuth, getECIndex()+1, nvIndexSize(getECIndex()+1));
            return TpmUtils.concat(part1, part2);
        } else {
            log.debug("Requested credential doesn't exist");
            throw new Tpm.TpmCredentialMissingException("Requested credential doesn't exist");
        }
    }

    //There is no hardware dependency for following functions hence using as it is from v12
    @Override
    public String getModuleLog() throws IOException, TpmException {
        return new TpmLinuxV12(null).getModuleLog();
    }

    @Override
    public String getTcbMeasurement() throws IOException, TpmException {
        return new TpmLinuxV12(null).getTcbMeasurement();
    }

    private int getECIndex() {
        return 0x01c00000;
    }
}
