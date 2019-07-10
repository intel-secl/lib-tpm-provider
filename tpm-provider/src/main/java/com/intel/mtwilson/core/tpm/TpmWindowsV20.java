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
}
