/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import tss.TpmDeviceBase;

import java.io.IOException;
import java.util.List;

/**
 *
 * @author dczech
 */
class TpmWindowsV20 extends TpmV20 {

    TpmWindowsV20(TpmDeviceBase base) {
        super(base);
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, TpmException {
        throw new UnsupportedOperationException("TpmWindows.takeOwnership the Windows Operating System manages ownership of the TPM at the system level");
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

    /**
     *
     * @return
     * @throws IOException
     * @throws TpmException
     */
    @Override
    public List<String> getTcbMeasurements() throws IOException, TpmException {
        return new TpmWindowsV12(super.getTpmToolsPath()).getTcbMeasurements();
    }

    @Override
    public boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException {
        return true;
    }
}
