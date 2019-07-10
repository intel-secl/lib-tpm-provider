/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.PersistentIndex;
import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import gov.niarl.his.privacyca.TpmUtils;
import org.apache.commons.io.FileUtils;
import tss.TpmDeviceBase;
import tss.tpm.*;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.util.*;

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
        if(credentialBlob == null) {
            return;
        }
        int size = credentialBlob.length;
        boolean sizeTooBig = (size > NV_BUFFER_MAX);
        nvDefine(ownerAuth, ownerAuth, getECIndex(), size, Tpm.NVAttribute.AUTHWRITE, Tpm.NVAttribute.AUTHREAD);
        byte[] part1Buf = Arrays.copyOfRange(credentialBlob, 0, sizeTooBig?NV_BUFFER_MAX:size);
        nvWrite(ownerAuth, getECIndex(), part1Buf, 0);
        if (sizeTooBig) {
            byte[] part2Buf = Arrays.copyOfRange(credentialBlob, NV_BUFFER_MAX, credentialBlob.length);
            nvWrite(ownerAuth, getECIndex(), part2Buf, NV_BUFFER_MAX);
        }
    }

    //There is no hardware dependency for following functions hence using as it is from v12
    @Override
    public String getModuleLog() throws IOException, TpmException {
        File measureLogFile = Paths.get("/opt", "trustagent", "var", "measureLog.xml").toFile();
        String content;
        if (measureLogFile.exists()) {
            content = FileUtils.readFileToString(measureLogFile);
        } else {
            File outFile = null;
            try {
                outFile = File.createTempFile("measureLog", ".xml");
                Map<String, String> variables = new HashMap<>();
                variables.put("OUTFILE", outFile.getAbsolutePath());
                TpmTool command = new TpmTool(getTpmToolsPath(), "module_analysis.sh");
                CommandLineResult result = command.execute(variables);
                if (result.getReturnCode() != 0) {
                    log.debug("Error running command [{}]: {}", command.getExecutable(), result.getStandardError());
                    throw new Tpm.TpmException("TpmLinux.getModuleLog module_analysis.sh returned nonzero error", result.getReturnCode());
                }
                log.debug("command stdout: {}", result.getStandardOut());
                content = FileUtils.readFileToString(outFile);
            } catch (Tpm.TpmException ex) {
                throw new Tpm.TpmException(ex);
            } catch (IOException ex) {
                throw new IOException(ex);
            } finally {
                if (outFile!=null) {
                    boolean deletedOutFile = outFile.delete();
                    if (!deletedOutFile) {
                        outFile.deleteOnExit();
                    }
                }
            }
        }
        return getModulesFromMeasureLogXml(content);
    }

    @Override
    public String getTcbMeasurement() throws IOException, TpmException {
        File tcbMeasurementFile = Paths.get("/opt", "trustagent", "var", "measureLog.xml").toFile();
        if (tcbMeasurementFile.exists()) {
            return FileUtils.readFileToString(tcbMeasurementFile, Charset.forName("UTF-8"));
        } else {
            log.debug("TpmLinux.getTcbMeasurement measurement.xml does not exist");
            throw new Tpm.TpmTcbMeasurementMissingException("TpmLinux.getTcbMeasurement measurement.xml does not exist");
        }
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
}
