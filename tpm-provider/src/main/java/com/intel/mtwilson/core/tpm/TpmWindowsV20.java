/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import tss.TpmDeviceBase;
import java.io.IOException;

/**
 *
 * @author dczech
 */
class TpmWindowsV20 extends TpmV20 {
    TpmWindowsV20(String tpmToolsPath, TpmDeviceBase base) {
        super(tpmToolsPath, base);
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, TpmException {
        throw new UnsupportedOperationException("TpmWindows.takeOwnership the Windows Operating System manages ownership of the TPM at the system level");
    }

    @Override
    public void setCredential(byte[] ownerAuth, CredentialType credentialType, byte[] credential) {
        throw new UnsupportedOperationException("TpmWindows.setCredential is not currently supported yet");
    }

    @Override
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, TpmException {
        throw new UnsupportedOperationException("TpmWindows.getEndorsementKeyModulus is not currently supported yet");
    }

    @Override
    public byte[] getCredential(byte[] ownerAuth, Tpm.CredentialType credentialType) throws Tpm.TpmException, IOException {
        return new TpmWindowsV12(super.getTpmToolsPath()).getCredential(ownerAuth, credentialType);
    }

    @Override
    public String getModuleLog() throws IOException, TpmException {
        return new TpmWindowsV12(super.getTpmToolsPath()).getModuleLog();
    }

    @Override
    public String getTcbMeasurement() throws IOException, TpmException {
        return new TpmWindowsV12(super.getTpmToolsPath()).getTcbMeasurement();
    }
}
