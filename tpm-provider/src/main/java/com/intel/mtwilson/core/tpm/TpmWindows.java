/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.CertifiedKey;
import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import com.intel.mtwilson.core.tpm.shell.TpmToolWindows;
import com.intel.mtwilson.core.tpm.util.Utils;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import gov.niarl.his.privacyca.TpmUtils;
import java.io.File;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import org.apache.commons.io.FileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author dczech
 */
abstract class TpmWindows extends Tpm {

    private final static Logger LOG = LoggerFactory.getLogger(TpmWindows.class);

    TpmWindows() {
        super();
    }

    TpmWindows(String tpmToolsPath) {
        super(tpmToolsPath);
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, TpmException {
        throw new UnsupportedOperationException("TpmWindows.takeOwnership the Windows Operating System manages ownership of the TPM at the system level");
    }
    
    /**
     *
     * @param ownerAuth
     * @return
     */
    @Override
    public boolean isOwnedWithAuth(byte[] ownerAuth) {
        return true;
    }

    @Override
    public byte[] getCredential(byte[] ownerAuth, CredentialType credentialType) throws IOException, TpmException {
        if (credentialType == null) {
            LOG.debug("TpmWindows.getCredential credentialType is null");
            throw new IllegalArgumentException("TpmWindows.getCredential credentialType is null");
        }
        if (credentialType != CredentialType.EC) {
            LOG.debug("TpmWindows.getCredential only CredentialType.EC is currently supported");
            throw new UnsupportedOperationException("TpmWindows.getCredential only CredentialType.EC is currently supported");
        }
        TpmTool getEkCert = new TpmToolWindows(getTpmToolsPath(), "GetEkCert");
        CommandLineResult result = getEkCert.execute();
        if (result.getReturnCode() != 0) {
            throw new TpmException("TpmWindows.getCredential GetEkCert returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 1) {
            LOG.debug("TpmWindows.getCredential GetEkCert expected at least 1 result. Received 0");
            throw new TpmException("TpmWindows.getCredential GetEkCert expected at least 1 result. Received 0");
        }
        byte[] cert = Utils.hexStringToByteArray(result.getLastLineToken(0).trim());
        LOG.debug("TpmWindows.getCredential Endorsement Certificate length: {}", cert.length);
        return cert;
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
    public abstract IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, TpmException;

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
    public CertifiedKey createAndCertifyKey(KeyType keyType, byte[] keyAuth, byte[] aikAuth) throws IOException, TpmException {
        if (keyType == null) {
            LOG.debug("TpmWindows.createAndCertifyKey keyType is null");
            throw new IllegalArgumentException("TpmWindows.createAndCertifyKey keyType is null");
        }
        if (keyAuth == null) {
            LOG.debug("TpmWindows.createAndCertifyKey keyAuth is null");
            throw new IllegalArgumentException("TpmWindows.createAndCertifyKey keyAuth is null");
        }
        String methodName;
        switch (keyType) {
            case BIND:
                methodName = "createbindingkey";
                break;
            case SIGN:
                methodName = "createsigningkey";
                break;
            default:
                throw new IllegalArgumentException("TpmWindows.createAndCertifyKey keyType is not BIND or SIGN");
        }
        LOG.info("UserName : {}", System.getProperty("user.name"));
        TpmTool createKey = new TpmToolWindows(getTpmToolsPath(), methodName);
        createKey.addArgument(keyType.toString());
        createKey.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
        CommandLineResult result = createKey.execute();
        if (result.getReturnCode() != 0) {
            throw new TpmException("TpmWindows.createAndCertifyKey " + methodName + " returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 2) {
            LOG.debug("TpmWindows.createAndCertifyKey " + methodName + " expected at least 2 results. Received {}", result.getLastLineTokenCount());
            throw new TpmException("TpmWindows.createAndCertifyKey " + methodName + " expected at least 2 results. Received " + result.getLastLineTokenCount());
        }
        LOG.info("TpmWindows.createAndCertifyKey call to {} was successful", methodName);
        LOG.info("TpmWindows.createAndCertifyKey keymod byteArray: {}", TpmUtils.hexStringToByteArray(result.getLastLineToken(0)));
        CertifiedKey key = new CertifiedKey();
        key.setKeyModulus(TpmUtils.hexStringToByteArray(result.getLastLineToken(0)));
        String aikName = KEY_NAME;
        String exportFile = keyType + "keyattestation";
        String nonce = Utils.byteArrayToHexString(Utils.randomBytes(20));
        TpmTool getKeyAttestation = new TpmToolWindows(getTpmToolsPath(), "GetKeyAttestation");
        getKeyAttestation.addArgument(keyType.toString());
        getKeyAttestation.addArgument(aikName);
        getKeyAttestation.addArgument(exportFile);
        getKeyAttestation.addArgument(nonce);
        getKeyAttestation.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
        getKeyAttestation.addArgument(TpmUtils.byteArrayToHexString(aikAuth));
        result = getKeyAttestation.execute();
        if (result.getReturnCode() != 0) {
            throw new TpmException("TpmWindows.createAndCertifyKey GetKeyAttestation returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 3) {
            LOG.debug("TpmWindows.createAndCertifyKey GetKeyAttestation exepcted at least 3 results. Received {}", result.getLastLineTokenCount());
            throw new TpmException("TpmWindows.createAndCertifyKey GetKeyAttestation exepcted at least 3 results. Received " + result.getLastLineTokenCount());
        }
        LOG.info("TpmWindows.createAndCertifyKey Call to GetKeyAttestation was successful");
        LOG.info("TpmWindows.createAndCertifyKey Result Count: {}", result.getLastLineTokenCount());
        key.setKeyData(Utils.hexStringToByteArray(result.getLastLineToken(0)));
        key.setKeySignature(Utils.hexStringToByteArray(result.getLastLineToken(1)));
        key.setKeyBlob(Utils.hexStringToByteArray(result.getLastLineToken(2)));
        return key;
    }

    @Override
    public void setAssetTag(byte[] ownerAuth, byte[] assetTagHash) throws IOException, TpmException {
        byte[] randPasswd = Utils.randomBytes(20);
        int index = getAssetTagIndex();
        if (nvIndexExists(index)) {
            LOG.debug("TpmWindows.setAssetTag index exists, releasing index...");
            nvRelease(ownerAuth, index);
            LOG.debug("TpmWindows.setAssetTag creating new index...");
        } else {
            LOG.debug("TpmWindows.setAssetTag index does not exist, creating it...");
        }
        nvDefine(ownerAuth, randPasswd, index, 32, EnumSet.of(NVAttribute.AUTHWRITE));
        nvWrite(randPasswd, index, assetTagHash);
        LOG.debug("TpmWindows.setAssetTag provisioned asset tag");
    }

    @Override
    public byte[] readAssetTag(byte[] ownerAuth) throws IOException, TpmException {
        int index = getAssetTagIndex();
        LOG.debug("TpmWindows.readAssetTag reading asset tag at index {} ...", index);
        if (nvIndexExists(index)) {
            LOG.debug("TpmWindows.readAssetTag asset tag index {} exists", index);
            return nvRead(ownerAuth, index, 32); //change the size to 32 bytes since we are using sha256 of asset tag
        } else {
            throw new TpmException("TpmWindows.readAssetTag asset tag has not been provisioned on this TPM");
        }
    }

    @Override
    public abstract int getAssetTagIndex();

    @Override
    public abstract Set<PcrBank> getPcrBanks() throws IOException, TpmException;

    @Override
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<NVAttribute> attributes) throws IOException, TpmException {
        TpmTool nvDefine = new TpmToolWindows(getTpmToolsPath(), "nvdefine");
        nvDefine.addArgument("0x" + Integer.toHexString(index));
        nvDefine.addArgument("0x" + Integer.toHexString(size));
        nvDefine.addArgument(TpmUtils.byteArrayToHexString(indexPassword));
        nvDefine.addArgument(attributes.toString());
        CommandLineResult result = nvDefine.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.nvDefine nvdefine returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmWindows.nvDefine nvdefine returned nonzero error", result.getReturnCode());
        }
    }

    @Override
    public void nvRelease(byte[] ownerAuth, int index) throws IOException, TpmException {
        TpmTool nvRelease = new TpmToolWindows(getTpmToolsPath(), "nvrelease");
        nvRelease.addArgument("0x" + Integer.toHexString(index));
        CommandLineResult result = nvRelease.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.nvRelease nvrelease returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmWindows.nvRelease nvrelease returned nonzero error", result.getReturnCode());
        }
    }

    @Override
    public void nvWrite(byte[] authPassword, int index, byte[] data) throws IOException, TpmException {
        TpmTool nvWrite = new TpmToolWindows(getTpmToolsPath(), "nvwrite");
        nvWrite.addArgument("0x" + Integer.toHexString(index));
        nvWrite.addArgument(TpmUtils.byteArrayToHexString(authPassword));
        nvWrite.addArgument(TpmUtils.byteArrayToHexString(data));
        CommandLineResult result = nvWrite.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.nvWrite nvwrite returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmWindows.nvWrite nvwrite returned nonzero error", result.getReturnCode());
        }
    }

    @Override
    public boolean nvIndexExists(int index) throws IOException, TpmException {
        LOG.debug("TpmWindows.nvIndexExists checking if index {} exists...", index);
        TpmTool nvInfo = new TpmToolWindows(getTpmToolsPath(), "nvinfo");
        nvInfo.addArgument("0x" + Integer.toHexString(index));
        CommandLineResult result = nvInfo.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.nvIndexExists nvinfo returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmWindows.nvIndexExists nvinfo returned nonzero error", result.getReturnCode());
        } else {
            return (result.getStandardOut().contains("NVRAM index"));
        }
    }

    @Override
    public byte[] nvRead(byte[] ownerAuth, int index, int size) throws IOException, TpmException {
        TpmTool nvRead = new TpmToolWindows(getTpmToolsPath(), "nvread");
        nvRead.addArgument("0x" + Integer.toHexString(index));
        nvRead.addArgument("0x" + Integer.toHexString(size));
        CommandLineResult result = nvRead.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.nvRead nvread returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmWindows.nvRead nvread returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 1) {
            LOG.debug("TpmWindows.nvRead expected at least 1 result. Received 0");
            throw new TpmException("TpmWindows.nvRead expected at least 1 result. Received 0");
        }
        return Utils.hexStringToByteArray(result.getLastLineToken(0));
    }

    private static boolean isAIKImported = false;
    @Override
    public TpmQuote getQuote(Set<PcrBank> pcrBanks, Set<Pcr> pcrs, byte[] aikBlob, byte[] aikAuth, byte[] nonce)
            throws IOException, TpmException {
        // import AIK
        if (!isAIKImported) {
            File aikFile = null;
            try {
                aikFile = File.createTempFile("aik", ".opaque");
                FileUtils.writeByteArrayToFile(aikFile, aikBlob);
                TpmTool importAik = new TpmToolWindows(getTpmToolsPath(), "importaik");
                importAik.addArgument(aikFile.getAbsolutePath());
                importAik.addArgument(KEY_NAME);
                LOG.info(importAik.toString());
                CommandLineResult result = importAik.execute();
                LOG.info(result.getStandardOut());
                LOG.info(result.getStandardError());
                if (result.getReturnCode() != 0) {
                    LOG.debug("TpmWindows.getQuote failed to import AIK with error {}", result.getReturnCode());
                    throw new TpmException("TpmWindows.getQuote failed to import AIK");
                }
                isAIKImported = true;
            } catch (TpmException ex) {
                throw new TpmException(ex);
            } catch (IOException ex) {
                throw new IOException(ex);
            } finally {
                // else delete the file when the program ends
                if (aikFile != null) {
                    boolean deletedAikFile = aikFile.delete();
                    if (!deletedAikFile) {
                        aikFile.deleteOnExit();
                    }
                }
            }
        }
        File quoteFile = Utils.getTempFile("aikquote", "tmp");
        TpmTool aikQuote = new TpmToolWindows(getTpmToolsPath(), "aikquote");
        aikQuote.addArgument(TpmUtils.byteArrayToHexString(KEY_NAME.getBytes()));
        aikQuote.addArgument(TpmUtils.byteArrayToHexString(quoteFile.getAbsolutePath().getBytes()));
        aikQuote.addArgument(TpmUtils.byteArrayToHexString(nonce));
        CommandLineResult result = aikQuote.execute();
        if(result.getReturnCode() != 0) {
            LOG.debug("TpmWindows.getQuote aikquote returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmWindows.getQuote aikquote returned nonzero error", result.getReturnCode());
        }
        TpmQuote quote = new TpmQuote(System.currentTimeMillis(), pcrBanks, FileUtils.readFileToByteArray(quoteFile));
        return quote;
    }

    /**
     *
     * @return
     * @throws IOException
     * @throws TpmException
     */
    @Override
    public String getModuleLog() throws IOException, TpmException {
        // In Windows, there is no script to prepare the xml with module measurements.
        // We only show 'tbootxm' module for PCR14. Read the measurement and prepare the xml content.
        File measurementFile = new File("C:\\Windows\\Logs\\MeasuredBoot\\measurement.sha1");
        if (measurementFile.exists()) {
            String measurement = FileUtils.readFileToString(measurementFile);
            String content = "<measureLog><txt><modules><module><pcrBank>SHA1</pcrBank><pcrNumber>14</pcrNumber><name>tbootxm</name><value>" + measurement + "</value></module></modules></txt></measureLog>";
            LOG.debug("Content of the XML file after reading measurement {} ", content);
            return getModulesFromMeasureLogXml(content);
        } else {
            LOG.debug("No measurement file available for reading tbootxm measurement");
            return null;
        }
    }

    /**
     *
     * @return
     * @throws IOException
     * @throws TpmException
     */
    @Override
    public List<String> getTcbMeasurements() throws IOException, TpmException {
        File tcbMeasurementdir = Paths.get("/Windows", "Logs", "MeasuredBoot").toFile();
        return getTcbMeasurements(tcbMeasurementdir);
    }

}