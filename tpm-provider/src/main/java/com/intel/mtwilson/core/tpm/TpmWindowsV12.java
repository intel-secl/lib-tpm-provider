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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.EnumSet;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import gov.niarl.his.privacyca.*;
import java.nio.BufferUnderflowException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 *
 * @author dczech
 */
class TpmWindowsV12 extends TpmWindows {
    private final static org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TpmWindowsV12.class);
    
    /**
     *
     * @param tpmToolsPath
     */
    public TpmWindowsV12(String tpmToolsPath) {
        super(tpmToolsPath);
    }
    
    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, TpmException {
        try {
            LOG.debug("TpmWindowsV12.collateIdentityRequest creating AIK...");
            byte[] pcaPubKeyBlob = new TpmPubKey((RSAPublicKey)pcaPubKey, 3, 1).toByteArray();
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
                throw new TpmException("TpmWindowsV12.collateIdentityRequest returned nonzero error", result.getReturnCode());
            }
            if(result.getLastLineTokenCount() < 2) {
                LOG.debug("TpmWindowsV12.collateIdentityRequest expected at least 2 results. Received {}", result.getLastLineTokenCount());
                throw new TpmException("TpmWindowsV12.collateIdentityRequest expected at least 2 results. Received " + result.getLastLineTokenCount());
            }
            byte[] endCreBytes;
            try {
                endCreBytes = getCredential(ownerAuth, CredentialType.EC);
            } catch(TpmException ex) {
                endCreBytes = null;
            }
            TpmIdentityProof idProof = new TpmIdentityProof(keyLabel.getBytes(),
                    TpmUtils.hexStringToByteArray(result.getLastLineToken(0)),
                    new TpmPubKey(TpmUtils.hexStringToByteArray(result.getLastLineToken(1))),
                    endCreBytes, endCreBytes, endCreBytes, false, false, false);
            TpmPubKey caPubKey = new TpmPubKey(new ByteArrayInputStream(pcaPubKeyBlob));
            TpmIdentityRequest idReq = new TpmIdentityRequest(idProof, caPubKey.getKey()); // this does the encryption of idProof by using caPubKey
            byte[] identityRequest = idReq.toByteArray();
            LOG.debug("identity request asym size: {}", idReq.getAsymBlob().length);
            byte[] aikModulus = TpmUtils.hexStringToByteArray(result.getLastLineToken(1));
            byte[] aikKeyBlob = TpmUtils.hexStringToByteArray(result.getLastLineToken(2));
            return new IdentityRequest(getTpmVersion(), identityRequest, aikModulus, aikKeyBlob, keyLabel.getBytes());
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(TpmWindowsV20.class.getName()).log(Level.SEVERE, null, ex);
            throw new TpmException("TpmWindowsV12.collateIdentityRequest MessageDigest.getInstance(SHA1) failed", ex);
        } catch (TpmUtils.TpmUnsignedConversionException | TpmUtils.TpmBytestreamResouceException | InvalidKeySpecException | IllegalBlockSizeException 
                | BadPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchPaddingException ex) {
            Logger.getLogger(TpmWindowsV12.class.getName()).log(Level.SEVERE, null, ex);
            throw new TpmException("TpmWindowsV12.collateIdentityRequest failed", ex);
        }
    }

    @Override
    public byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest)
            throws IOException, TpmException {
        String hisIdentityLabel = KEY_NAME;
        TpmTool activateIdentity = new TpmToolWindows(getTpmToolsPath(), "ActivateIdentity");
        activateIdentity.addArgument(TpmUtils.byteArrayToHexString(hisIdentityLabel.getBytes()));
        activateIdentity.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
        activateIdentity.addArgument(TpmUtils.byteArrayToHexString(proofRequest.getEkBlob()));
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
        return 0x40000010;
    }

    @Override
    public Set<PcrBank> getPcrBanks() throws IOException, TpmException {
        return EnumSet.of(PcrBank.SHA1);
    }

    @Override
    public String getTpmVersion() {
        return "1.2";
    }
}
