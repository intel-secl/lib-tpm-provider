/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import com.intel.mtwilson.core.tpm.shell.TpmToolWindows;
import com.intel.mtwilson.core.tpm.util.Utils;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import gov.niarl.his.privacyca.TpmPubKey;
import gov.niarl.his.privacyca.TpmUtils;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.EnumSet;
import java.util.Set;

/**
 *
 * @author dczech
 */
class TpmWindowsV20 extends TpmWindows {

    private final static org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TpmWindowsV20.class);

    TpmWindowsV20(String tpmToolsPath) {
        super(tpmToolsPath);
    }

    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, TpmException {
        try {
            LOG.debug("TpmWindowsV20.collateIdentityRequest creating AIK...");
            byte[] pcaPubKeyBlob = new TpmPubKey((RSAPublicKey) pcaPubKey, 3, 1).toByteArray();
            String keyLabel = KEY_NAME;
            MessageDigest md = MessageDigest.getInstance("SHA1");
            byte[] idLabelBytes = keyLabel.getBytes();
            byte[] chosenId = new byte[idLabelBytes.length + pcaPubKeyBlob.length];
            System.arraycopy(idLabelBytes, 0, chosenId, 0, idLabelBytes.length);
            System.arraycopy(pcaPubKeyBlob, 0, chosenId, idLabelBytes.length, pcaPubKeyBlob.length);
            md.update(chosenId);
            byte[] chosenIdHash = md.digest();
            TpmTool collate = new TpmToolWindows(getTpmToolsPath(), "CollateIdentityRequest");
            collate.addArgument(TpmUtils.byteArrayToHexString(keyLabel.getBytes()));
            collate.addArgument(TpmUtils.byteArrayToHexString(chosenIdHash));
            collate.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
            CommandLineResult result = collate.execute();
            if (result.getReturnCode() != 0) {
                LOG.debug("TpmWiniodowsV20.collateIdentityRequest returned nonzero error {}", result.getReturnCode());
                throw new TpmException("TpmWindowsV20.collateIdentityRequest returned nonzero error", result.getReturnCode());
            }
            if (result.getLastLineTokenCount() < 3) {
                LOG.debug("TpmWindowsV20.collateIdentityRequest expected at least 3 results. Received {}", result.getLastLineTokenCount());
                throw new TpmException("TpmWindowsV20.collateIdentityRequest expected at least 3 results. Received " + result.getLastLineTokenCount());
            }
            byte[] aikName = Utils.hexStringToByteArray(result.getLastLineToken(0));
            byte[] aikPubModulus = Utils.hexStringToByteArray(result.getLastLineToken(1));
            byte[] aikKeyBlob = Utils.hexStringToByteArray(result.getLastLineToken(2));
            return new IdentityRequest(getTpmVersion(), aikPubModulus, aikPubModulus, aikKeyBlob, aikName);
        } catch (NoSuchAlgorithmException ex) {
            LOG.debug("TpmWindowsV20.collateIdentityRequest MessageDigest.getInstance(SHA1) failed", ex);
            throw new TpmException("TpmWindowsV20.collateIdentityRequest MessageDigest.getInstance(SHA1) failed", ex);
        } catch (TpmUtils.TpmUnsignedConversionException ex) {
            LOG.debug("TpmWindowsV20.collateIdentityRequest failed to parse pcaPubKey", ex);
            throw new TpmException("TpmWindowsV20.collateIdentityRequest failed to parse pcaPubKey", ex);
        }
    }

    @Override
    public byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest)
            throws IOException, TpmException {
        String hisIdentityLabel = KEY_NAME;
        TpmTool activateIdentity = new TpmToolWindows(getTpmToolsPath(), "ActivateIdentity");
        activateIdentity.addArgument(TpmUtils.byteArrayToHexString(hisIdentityLabel.getBytes()));
        activateIdentity.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
        byte[] asym = Utils.fixMakeCredentialBlobForWindows(TpmUtils.concat(proofRequest.getCredential(), proofRequest.getSecret()));
        activateIdentity.addArgument(TpmUtils.byteArrayToHexString(asym));
        CommandLineResult result = activateIdentity.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.activateIdentity ActivateIdentity returned nonzero error");
            LOG.debug(result.getStandardOut());
            LOG.debug(result.getStandardError());
            throw new TpmException("TpmWindows.activateIdentity ActivateIdentity returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 2) {
            LOG.debug("TpmWindows.activateIdentity ActivateIdentity expected at least 2 results. Received {}", result.getLastLineTokenCount());
            throw new TpmException("TpmWindows.activateIdentity ActivateIdentity expected at least 2 results. Received " + result.getLastLineTokenCount());
        }
        try {
            return Utils.decryptSymCaAttestation(Utils.hexStringToByteArray(result.getLastLineToken(0)), proofRequest.getSymBlob());
        } catch (BufferUnderflowException | Utils.SymCaDecryptionException ex) {
            LOG.debug("TpmWindows.activateIdentity decryptSymCaAttestation failed with exception {}", ex);
            throw new TpmException("TpmWindows.activateIdentity decryptSymCaAttestaion failed with exception", ex);
        }
    }

    @Override
    public int getAssetTagIndex() {
        return 0x01c10110;
    }

    @Override
    public Set<PcrBank> getPcrBanks() throws IOException, TpmException {
        TpmTool getbanks = new TpmTool(getTpmToolsPath(), ("TPMTool.exe"));
        getbanks.addArgument("getpcrbanks");
        CommandLineResult result = getbanks.execute();
        Set<Tpm.PcrBank> pcrBanks = EnumSet.noneOf(Tpm.PcrBank.class);
        if (result.getReturnCode() == 0) {
            String[] str = result.getStandardOut().split(" ");
            for(String bank: str){
                switch(bank){
                    case "SHA1" :
                        pcrBanks.add(PcrBank.SHA1);
                        break;
                    case "SHA256" :
                        pcrBanks.add(PcrBank.SHA256);
                        break;
                    case "SHA384" :
                        pcrBanks.add(PcrBank.SHA384);
                        break;
                    case "SHA512" :
                        pcrBanks.add(PcrBank.SHA512);
                        break;
                    case "SM3_256" :
                        pcrBanks.add(PcrBank.SM3_256);
                        break;
                }
            }
        }
        if (pcrBanks.isEmpty()) {
            LOG.debug("TpmWindowsV20.getPcrBanks failed to retrieve list of PCR banks");
            throw new Tpm.TpmException("TpmWindowsV20.getPcrBanks failed to retrieve list of PCR Banks");
        }
        return pcrBanks;
    }

    @Override
    public String getTpmVersion() {
        return "2.0";
    }

}
