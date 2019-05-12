/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.PersistentIndex;
import gov.niarl.his.privacyca.TpmUtils;
import tss.TpmDeviceBase;
import tss.tpm.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.ArrayList;
import java.util.List;

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
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, Tpm.TpmException {
        changeAuth(newOwnerAuth);

        // Create an RSA storage key in the owner hierarchy. This is
        // conventionally called an SRK
        TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.decrypt,
                        TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                        new TPMS_NULL_ASYM_SCHEME(),2048,0),
                new TPM2B_PUBLIC_KEY_RSA());

        CreatePrimaryResponse cpResponse;
        TPM_HANDLE oHandle = getOwnerHandle(newOwnerAuth);
        try {
            cpResponse = tpm.CreatePrimary(oHandle,
                    new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
        } catch (tss.TpmException e) {
            log.error("Failed to create storage primary key");
            throw new Tpm.TpmException("Failed to create storage primary key");
        }

        try {
            tpm.EvictControl(oHandle, cpResponse.handle,
                    TPM_HANDLE.from(PersistentIndex.PK.getValue()));
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("NV_DEFINED")) {
                log.error("Failed to make storage primary key persistent");
                throw new Tpm.TpmException("Failed to make storage primary key persistent");
            }
        }
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

    /**
     *
     * @param ownerAuth
     * @return
     * @throws IOException
     */
    @Override
    public boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException {
        return changeAuth(ownerAuth, ownerAuth);
    }

    private boolean changeAuth(byte[] oldAuth, byte[] newAuth) {
        List<TPM_HANDLE> handles = new ArrayList<>();
        handles.add(TPM_HANDLE.from(TPM_RH.OWNER));
        handles.add(TPM_HANDLE.from(TPM_RH.ENDORSEMENT));
        handles.add(TPM_HANDLE.from(TPM_RH.LOCKOUT));

        for (TPM_HANDLE handle : handles) {
            if (oldAuth != null) {
                handle.AuthValue = oldAuth;
            }
            try {
                tpm.HierarchyChangeAuth(handle, newAuth);
            } catch (tss.TpmException e) {
                return false;
            }
        }

        return true;
    }

    private void changeAuth(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        // take ownership and see if we can change it and revert it from a temporary
        if (!changeAuth(null, ownerAuth)) {
            byte[] newOwnerPass = TpmUtils.createRandomBytes(20);
            if (!changeAuth(ownerAuth, newOwnerPass)) {
                // supplied newOwnerAuth is invalid
                log.error("Cannot take ownership; TPM claimed with a different password");
                throw new Tpm.TpmException("Cannot take ownership; TPM claimed with a different password");
            } else {
                // supplied newOwnerAuth is valid, so change TPM owner pass back from the temporary and do it again
                if (!changeAuth(newOwnerPass, ownerAuth)) {
                    log.error("CRITICAL ERROR: Could not change TPM password back from temporary. TPM must be reset from bios");
                    throw new Tpm.TpmException("CRITICAL ERROR: "
                            + "Could not change TPM password back from temporary. TPM must be reset from bios");
                }
            }
        }
    }

    private int getECIndex() {
        return 0x01c00000;
    }
}
