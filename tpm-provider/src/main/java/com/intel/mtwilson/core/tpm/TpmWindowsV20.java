/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import gov.niarl.his.privacyca.TpmUtils;
import tss.TpmDeviceBase;
import java.io.IOException;

/**
 *
 * @author dczech
 */
class TpmWindowsV20 extends TpmV20 {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmWindowsV20.class);
    private static final int NV_BUFFER_MAX = 768;

    TpmWindowsV20(TpmDeviceBase base) {
        super(base);
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, TpmException {
        throw new UnsupportedOperationException("TpmWindows.takeOwnership the Windows Operating System manages ownership of the TPM at the system level");
    }

    @Override
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, TpmException {
        throw new UnsupportedOperationException("TpmWindows.getEndorsementKeyModulus is not currently supported yet");
    }

    @Override
    public void setCredential(byte[] ownerAuth, CredentialType credentialType, byte[] credential) {
        throw new UnsupportedOperationException("TpmWindows.setCredential is not currently supported yet");
    }

    @Override
    public byte[] getCredential(byte[] ownerAuth, Tpm.CredentialType credentialType) throws Tpm.TpmException, IOException {
        if (credentialType != Tpm.CredentialType.EC) {
            throw new UnsupportedOperationException("Credential Types other than EC (Endorsement Credential) are not yet supported");
        }
        if(nvIndexExists(getECIndex())) {
            int size = nvIndexSize(getECIndex());
            boolean sizeTooBig = (size > NV_BUFFER_MAX);
            byte[] part1 = nvRead(null, getECIndex(), sizeTooBig?NV_BUFFER_MAX:size, 0);
            byte[] part2 = new byte[0];
            if (sizeTooBig) {
                part2 = nvRead(null, getECIndex(), size-NV_BUFFER_MAX, NV_BUFFER_MAX);
            }
            return TpmUtils.concat(part1, part2);
        } else {
            log.debug("Requested credential doesn't exist");
            throw new Tpm.TpmCredentialMissingException("Requested credential doesn't exist");
        }
    }

    //There is no hardware dependency for following functions hence using as it is from v12
    @Override
    public String getModuleLog() throws IOException, TpmException {
        return new TpmWindowsV12(super.getTpmToolsPath()).getModuleLog();
    }

    @Override
    public String getTcbMeasurement() throws IOException, TpmException {
        return new TpmWindowsV12(super.getTpmToolsPath()).getTcbMeasurement();
    }

    @Override
    public boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException {
        return true;
    }

    private int getECIndex() {
        return 0x01c00002;
    }
}
