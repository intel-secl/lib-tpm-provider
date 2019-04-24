/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import com.intel.mtwilson.core.tpm.shell.TpmToolNiarl;
import com.intel.mtwilson.core.tpm.util.Utils;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import gov.niarl.his.privacyca.TpmPubKey;
import gov.niarl.his.privacyca.TpmUtils;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.interfaces.RSAPublicKey;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;

/**
 *
 * @author dczech
 */
class TpmLinuxV12 extends Tpm {

    final static int AIK_INDEX = 1;
    final static int BINDING_KEY_INDEX = 3;
    final static int SIGNING_KEY_INDEX = 4;

    private final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TpmLinuxV12.class);

    /**
     * Default Constructor
     */
    protected TpmLinuxV12() {
        super();
    }

    /**
     * Constructor with User Specified TPM Tools Path
     *
     * @param tpmToolsPath
     */
    protected TpmLinuxV12(String tpmToolsPath) {
        super(tpmToolsPath);
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, TpmException {
        /*
         * Take Ownership
         * NIARL_TPM_Module -mode 1 -owner_auth <40 char hex blob> -nonce <40 char hex blob>
         * return: no return ***
         */
        byte[] nonce = TpmUtils.createRandomBytes(20);
        TpmTool tool = new TpmToolNiarl(getTpmToolsPath(), 1, false);
        tool.addArgument("-owner_auth");
        tool.addArgument(TpmUtils.byteArrayToHexString(newOwnerAuth));
        tool.addArgument("-nonce");
        tool.addArgument(TpmUtils.byteArrayToHexString(nonce));
        CommandLineResult result = tool.execute();
        if (result.getReturnCode() != 0) {
            if (result.getReturnCode() == 4) {
                LOG.info("TpmLinuxV12.takeOwnership failed: ownership already taken");
                throw new TpmOwnershipAlreadyTakenException("TpmLinuxV12.takeOwnership failed: ownership already taken", result.getReturnCode());
            }
            LOG.debug("TpmLinuxV12.takeOwnership failed: return code {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV12.takeOwnership failed", result.getReturnCode());
        }
    }

    @Override
    public byte[] getCredential(byte[] ownerAuth, CredentialType credentialType) throws IOException, TpmException {
        /*
         * Get Credential (EC, PC, CC, and PCC)
         * NIARL_TPM_Module -mode 13 -owner_auth <40 char hex blob> -cred_type <"EC" | "CC" | "PC" | "PCC"> [-trousers]
         * return: <cred blob>
         */
        if (!(credentialType == CredentialType.EC || credentialType == CredentialType.CC || credentialType == CredentialType.PC
                || credentialType == CredentialType.PCC)) {
            throw new TpmException("TpmLinuxV12.getCredential: credential type parameter must be \"EC\", \"CC\", \"PC\", or \"PCC\".");
        }
        // TROUSERS MODE OPTIONAL
        TpmTool tool = new TpmToolNiarl(getTpmToolsPath(), 13, true);
        tool.addArgument("-owner_auth");
        tool.addArgument(TpmUtils.byteArrayToHexString(ownerAuth));
        tool.addArgument("-cred_type");
        tool.addArgument(credentialType.toString());
        CommandLineResult result = tool.execute();
        if (result.getReturnCode() != 0) {
            if (result.getReturnCode() == 2) {
                LOG.debug("TpmLinuxV12.getCredential could not find requested credential of type {}", credentialType.toString());
                throw new TpmCredentialMissingException("TpmLinuxV12.getCredential could not find requested credential of type "
                        + credentialType.toString(), result.getReturnCode());
            }
            LOG.debug("TpmLinuxV12.getCredential returned nonzero error: {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV12.getCredential returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 1) {
            LOG.debug("TpmLinuxV12.getCredential expected at least 1 result. Received 0");
            throw new TpmException("TpmLinuxV12.getCredential expected at least 1 result. Received 0");
        }
        return Utils.hexStringToByteArray(result.getLastLineToken(0));
    }

    @Override
    public void setCredential(byte[] ownerAuth, CredentialType credentialType, byte[] credentialBlob) throws IOException, TpmException {
        /*
         * Set Credential (EC, PC, CC, and PCC)
         * NIARL_TPM_Module -mode 12 -owner_auth <40 char hex blob> -cred_type <"EC" | "CC" | "PC" | "PCC"> -blob <>[-trousers]
         * return: no return ***
         */
        if (!(credentialType == CredentialType.EC || credentialType == CredentialType.CC || credentialType == CredentialType.PC
                || credentialType == CredentialType.PCC)) {
            LOG.debug("TpmLinuxV12.setCredential: credential type parameter must be \"EC\", \"CC\", \"PC\", or \"PCC\".");
            throw new TpmException("TpmLinuxV12.setCredential: credential type parameter must be \"EC\", \"CC\", \"PC\", or \"PCC\".");
        }
        // TROUSERS MODE OPTIONAL
        TpmTool tool = new TpmToolNiarl(getTpmToolsPath(), 12, true);
        tool.addArgument("-owner_auth");
        tool.addArgument(TpmUtils.byteArrayToHexString(ownerAuth));
        tool.addArgument("-cred_type");
        tool.addArgument(credentialType.toString());
        tool.addArgument("-blob");
        tool.addArgument(TpmUtils.byteArrayToHexString(credentialBlob));
        CommandLineResult result = tool.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV12.setCredential returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV12.setCredential returned nonzero error", result.getReturnCode());
        }
    }

    @Override
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, TpmException {
        /*
         * Get Key (EK) *
         * NIARL_TPM_Module -mode 10 -key_type EK -owner_auth <40 char hex blob> -nonce <40 char hex blob>
         * return: <modulus>
         */
        byte[] nonce = TpmUtils.createRandomBytes(20);
        TpmTool tool = new TpmToolNiarl(getTpmToolsPath(), 10, false);
        tool.addArgument("-key_type");
        tool.addArgument("ek");
        tool.addArgument("-owner_auth");
        tool.addArgument(TpmUtils.byteArrayToHexString(ownerAuth));
        tool.addArgument("-nonce");
        tool.addArgument(TpmUtils.byteArrayToHexString(nonce));
        CommandLineResult result = tool.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV12.getPublicEndorsementKey returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV12.getPublicEndorsementKey returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 1) {
            LOG.debug("TpmLinuxV12.getPublicEndorsementKey expected at least 1 result. Received 0");
            throw new TpmException("TpmLinuxV12.getPublicEndorsementKey expected at least 1 result. Received 0");
        }
        return Utils.hexStringToByteArray(result.getLastLineToken(0));
    }

    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, TpmException, CertificateEncodingException {
        try {
            /*
            * Collate Identity Request
            * NIARL_TPM_Module -mode 3 -owner_auth <40 char hex blob> -key_auth <40 char hex blob> -key_label <hex string in ASCII>
            * -pcak <public key blob for Privacy CA> -key_index <integer index> [-ec_blob <hex blob of endorsement credential> -ec_nvram -trousers]
            * return: <identity request> <aik modulus> <aik complete key blob>
             */
            TpmPubKey pcaPubKeyBlob = new TpmPubKey((RSAPublicKey) pcaPubKey, 3, 1);
            String keyLabel = KEY_NAME;
            TpmTool tool = new TpmToolNiarl(getTpmToolsPath(), 3, true);
            tool.addArgument("-owner_auth");
            tool.addArgument(TpmUtils.byteArrayToHexString(ownerAuth));
            tool.addArgument("-key_auth");
            tool.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
            tool.addArgument("-key_label");
            tool.addArgument(TpmUtils.byteArrayToHexString(keyLabel.getBytes()));
            tool.addArgument("-pcak");
            tool.addArgument(TpmUtils.byteArrayToHexString(pcaPubKeyBlob.toByteArray()));
            tool.addArgument("-key_index");
            tool.addArgument(Integer.toString(1));
            // TROUSERS MODE OPTIONAL
            CommandLineResult result = tool.execute();
            if (result.getReturnCode() != 0) {
                LOG.debug("TpmLinuxV12.collateIdentityRequest returned nonzero error {}", result.getReturnCode());
                throw new TpmException("TpmLinuxV12.collateIdentityRequest returned nonzero error", result.getReturnCode());
            }
            if (result.getLastLineTokenCount() < 3) {
                LOG.debug("TpmLinuxV12.collateIdentityRequest expected at least 3 results. Received {}", result.getLastLineTokenCount());
                throw new TpmException("TpmLinuxV12.collateIdentityRequest expected at least 3 results. Received " + result.getLastLineTokenCount());
            }
            byte[] identityRequest = Utils.hexStringToByteArray(result.getLastLineToken(0));
            byte[] aikMod = Utils.hexStringToByteArray(result.getLastLineToken(1));
            byte[] aikBlob = Utils.hexStringToByteArray(result.getLastLineToken(2));
            IdentityRequest toReturn = new IdentityRequest(getTpmVersion(), identityRequest, aikMod, aikBlob, keyLabel.getBytes());
            return toReturn;
        } catch (TpmUtils.TpmUnsignedConversionException ex) {
            LOG.debug("TpmLinuxV12.collateIdentityRequest failed to parse pcaPubKey", ex);
            throw new TpmException("TpmLinuxV12.collateIdentityRequest failed to parse pcaPubKey", ex);
        }
    }

    @Override
    public byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest)
            throws IOException, TpmException {
        /*
         * Activate Identity
         * NIARL_TPM_Module -mode 4 -owner_auth <40 char hex blob> -key_auth <40 char hex blob> -asym <> -sym <> -key_index <integer index>
         * return: <aik certificate>
         */
        TpmTool tool = new TpmToolNiarl(getTpmToolsPath(), 4, false);
        tool.addArgument("-owner_auth");
        tool.addArgument(TpmUtils.byteArrayToHexString(ownerAuth));
        tool.addArgument("-key_auth");
        tool.addArgument(TpmUtils.byteArrayToHexString(keyAuth));
        tool.addArgument("-asym");
        tool.addArgument(TpmUtils.byteArrayToHexString(proofRequest.getAsymBlob()));
        tool.addArgument("-sym");
        tool.addArgument(TpmUtils.byteArrayToHexString(proofRequest.getSymBlob()));
        tool.addArgument("-key_index");
        tool.addArgument(Integer.toString(1));
        CommandLineResult result = tool.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV12.activateIdentity returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV12.activateIdentity returned nonzero error", result.getReturnCode());
        }
        if (result.getLastLineTokenCount() < 2) {
            LOG.debug("TpmLinuxV12.activateIdentity expected at least 2 results. Received {}", result.getLastLineTokenCount());
            throw new TpmException("TpmLinuxV12.activateIdentity expected at least 2 results. Received " + result.getLastLineTokenCount());
        }
        HashMap<String, byte[]> results = new HashMap<>();
        results.put("aikblob", Utils.hexStringToByteArray(result.getLastLineToken(1)));
        return Utils.hexStringToByteArray(result.getLastLineToken(0));
    }

    @Override
    public void setAssetTag(byte[] ownerAuth, byte[] assetTagHash) throws IOException, TpmException {
        int index = getAssetTagIndex();
        byte[] randPasswd = Utils.randomBytes(20);
        boolean indexExists = nvIndexExists(getAssetTagIndex());
        if (indexExists) {
            LOG.debug("TpmLinuxV12.setAssetTag Index exists. Releasing index...");
            nvRelease(ownerAuth, index);
            LOG.debug("TpmLinuxV12.setAssetTag Creating new index...");
            nvDefine(ownerAuth, randPasswd, index, 32, EnumSet.of(NVAttribute.AUTHWRITE));
        } else {
            LOG.debug("TpmLinuxV12.setAssetTag Index does not exist. Creating it...");
            nvDefine(ownerAuth, randPasswd, index, 32, EnumSet.of(NVAttribute.AUTHWRITE));
        }
        nvWrite(randPasswd, index, assetTagHash);
        LOG.debug("TpmLinuxV12.setAssettag Provisioned asset tag");
    }

    @Override
    public byte[] readAssetTag(byte[] ownerAuth) throws IOException, TpmException {
        int index = getAssetTagIndex();
        LOG.debug("TpmLinuxV12.readAssetTag Checking if Asset Tag Index exists...");
        if (nvIndexExists(index)) {
            LOG.debug("TpmLinuxV12.readAssetTag Asset Tag Index {} exists", index);
            return nvRead(ownerAuth, index, 32);
        } else {
            throw new TpmException("Asset Tag has not been provisoined on this TPM");
        }
    }

    @Override
    public int getAssetTagIndex() {
        return 0x40000010;
    }

    @Override
    public Set<PcrBank> getPcrBanks() {
        return EnumSet.of(PcrBank.SHA1);
    }

    private Map<String, String> loadLibraryPathToEnvironmentVariables(Map<String, String> envVariables) {
        String LD_LIBRARY_PATH = System.getenv("LD_LIBRARY_PATH");
        if (LD_LIBRARY_PATH != null) {
            envVariables.put("LD_LIBRARY_PATH", LD_LIBRARY_PATH);
        }
        return envVariables;
    }

    private String nvAttributesToString(Set<NVAttribute> attributes) {
        return attributes.stream().sorted().map(attr -> attr.toString().toUpperCase()).collect(Collectors.joining("|"));
    }

    @Override
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<NVAttribute> attributes) throws IOException, TpmException {
        LOG.debug("TpmLinuxV12.nvDefine running command tpm_nvdefine -i " + index + " -s 0x" + Integer.toHexString(size)
                + " -x -aXXXX -oXXXX --permissions=" + attributes);
        Map<String, String> environmentVariables = new HashMap<>();
        loadLibraryPathToEnvironmentVariables(environmentVariables);
        environmentVariables.put("tpmOwnerPass", Utils.byteArrayToHexString(ownerAuth));
        environmentVariables.put("NvramPassword", Utils.byteArrayToHexString(indexPassword));
        TpmTool tool = new TpmTool(getTpmToolsPath(), "tpm_nvdefine");
        tool.addArgument("-x");
        tool.addArgument("-t");
        tool.addArgument("-aNvramPassword");
        tool.addArgument("-otpmOwnerPass");
        tool.addArgument("--permissions=" + nvAttributesToString(attributes));
        tool.addArgument("-s");
        tool.addArgument(String.format("0x%08x", size));
        tool.addArgument("-i");
        tool.addArgument(String.format("0x%08x", index));
        CommandLineResult result = tool.execute(environmentVariables);
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV12.nvDefine failed to define NVRAM index");
            throw new TpmException("TpmLinuxV12.nvDefine failed to define NVRAM index", result.getReturnCode());
        }
    }

    @Override
    public void nvRelease(byte[] ownerAuth, int index) throws IOException, TpmException {
        LOG.debug("TpmLinuxV12 running command tpm_nvrelease -x -t -i " + index + " -oXXXX");
        Map<String, String> environmentVariables = new HashMap<>();
        loadLibraryPathToEnvironmentVariables(environmentVariables);
        environmentVariables.put("tpmOwnerPass", Utils.byteArrayToHexString(ownerAuth));
        TpmTool tool = new TpmTool(getTpmToolsPath(), "tpm_nvrelease");
        tool.addArgument("-x");
        tool.addArgument("-t");
        tool.addArgument("-otpmOwnerPass");
        tool.addArgument("-i");
        tool.addArgument(String.format("0x%08x", index));
        CommandLineResult result = tool.execute(environmentVariables);
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV12.nvRelease tpm_nvrelease failed to release NVRAM index");
            throw new TpmException("TpmLinuxV12.nvRelease tpm_nvrelease failed to release NVRAM index", result.getReturnCode());
        }
    }

    @Override
    public byte[] nvRead(byte[] authPassword, int index, int size) throws IOException, TpmException {
        File f = File.createTempFile("nvread", ".data");
        try (FileInputStream fis = new FileInputStream(f)) {
            LOG.debug("TpmLinuxV12.nvRead running command tpm_nvread -i " + index + " -s " + size + " -f " + f.getPath());
            Map<String, String> environmentVariables = new HashMap<>();
            loadLibraryPathToEnvironmentVariables(environmentVariables);
            TpmTool tool = new TpmTool(getTpmToolsPath(), "tpm_nvread");
            tool.addArgument("-i");
            tool.addArgument(String.format("0x%08x", index));
            tool.addArgument("-s");
            tool.addArgument(String.format("0x%08x", size));
            tool.addArgument("-f");
            tool.addArgument(f.getAbsolutePath());
            CommandLineResult result = tool.execute(environmentVariables);
            if (result.getReturnCode() != 0) {
                LOG.debug("TpmLinuxV12.nvRead tpm_nvread failed to read from NVRAM");
                throw new TpmException("TpmLinuxV12.nvRead tpm_nvread failed to read from NVRAM", result.getReturnCode());
            }

            byte[] res = IOUtils.toByteArray(fis);
            return res;
        } finally {
            f.delete();
        }
    }

    @Override
    public void nvWrite(byte[] authPassword, int index, byte[] data) throws IOException, TpmException {
        File tmpFile = File.createTempFile("nvwrite", ".data");
        try (FileOutputStream output = new FileOutputStream(tmpFile)) {
            IOUtils.write(data, output);

            LOG.debug("TpmLinuxV12.nvWrite running command tpm_nvwrite -x -i " + index + " -pXXXX -f " + tmpFile.getPath());
            Map<String, String> environmentVariables = new HashMap<>();
            loadLibraryPathToEnvironmentVariables(environmentVariables);
            environmentVariables.put("NvramPassword", Utils.byteArrayToHexString(authPassword));
            TpmTool tool = new TpmTool(getTpmToolsPath(), "tpm_nvwrite");
            tool.addArgument("-x");
            tool.addArgument("-t");
            tool.addArgument("-pNvramPassword");
            tool.addArgument("-i");
            tool.addArgument(String.format("0x%08x", index));
            tool.addArgument("-f");
            tool.addArgument(tmpFile.getAbsolutePath());
            CommandLineResult result = tool.execute(environmentVariables);
            if (result.getReturnCode() != 0) {
                LOG.debug("TpmLinuxV12.nvWrite tpm_nvwrite failed to write to NVRAM");
                throw new TpmException("TpmLinuxV12.nvWrite tpm_nvwrite failed to write to NVRAM");
            }
        } finally {
            tmpFile.delete();
        }
    }

    @Override
    public boolean nvIndexExists(int index) throws IOException, TpmException {
        TpmTool tool = new TpmTool(getTpmToolsPath(), "tpm_nvinfo");
        tool.addArgument("-i");
        tool.addArgument(String.format("0x%08x", index));
        Map<String, String> environmentVariables = new HashMap<>();
        loadLibraryPathToEnvironmentVariables(environmentVariables);
        CommandLineResult result = tool.execute(environmentVariables);
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV12.nvIndexExists tpm_nvinfo failed");
            throw new TpmException("TpmLinuxV12.nvIndexExists tpm_nvinfo failed", result.getReturnCode());
        }
        return (result.getStandardOut() != null && result.getStandardOut().contains("NVRAM index"));
    }
    
    @Override
    public TpmQuote getQuote(Set<PcrBank> pcrBanks, Set<Pcr> pcrs, byte[] aikBlob, byte[] aikAuth, byte[] nonce)
            throws IOException, TpmException {
        byte[] quoteData;
        File tempNonceFile = null;
        File tempAikFile = null;
        File tempQuoteFile = null;
        try {
            // we need to dump nonce and aikBlob to temporary files. 
            tempNonceFile = File.createTempFile("nonce", "tmp");
            Files.write(tempNonceFile.toPath(), nonce, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            tempAikFile = File.createTempFile("aikblob", "tmp");
            Files.write(tempAikFile.toPath(), aikBlob, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
            tempQuoteFile = File.createTempFile("quote", "tmp");
            TpmTool tool = new TpmTool("/opt/trustagent/share/tpmagent/bin", "aikquote"); //aikquote is installed in this path instead of /opt/trustagent/bin
            tool.addArgument("-p");
            tool.addArgument(TpmUtils.byteArrayToHexString(aikAuth));
            tool.addArgument("-c");
            tool.addArgument(tempNonceFile.getAbsolutePath());
            tool.addArgument(tempAikFile.getAbsolutePath());
            pcrs.forEach((pcr) -> {
                tool.addArgument(Integer.toString(pcr.toInt()));
            });
            tool.addArgument(tempQuoteFile.getAbsolutePath());
            CommandLineResult result = tool.execute();
            if (result.getReturnCode() != 0) {
                LOG.debug("TpmLinuxV12.getQuote aikquote returned nonzero error", result.getReturnCode());
                throw new TpmException("TpmLinuxV12.getQuote aikquote returned nonzero error", result.getReturnCode());
            }
            // read data from the quote file we specified to the aikquote command
            quoteData = Files.readAllBytes(tempQuoteFile.toPath());
        } catch (TpmException ex) {
            throw new TpmException(ex);
        } catch (IOException ex) {
            throw new IOException(ex);
        } finally {
            if (tempNonceFile != null) {
                boolean deletedNonceFile = tempNonceFile.delete();
                if (!deletedNonceFile) {
                    tempNonceFile.deleteOnExit();
                }
            }
            if (tempAikFile != null) {
                boolean deletedAikFile = tempAikFile.delete();
                if (!deletedAikFile) {
                    tempAikFile.deleteOnExit();
                }
            }
            if (tempQuoteFile != null) {
                boolean deletedQuoteFile = tempQuoteFile.delete();
                if (!deletedQuoteFile) {
                    tempQuoteFile.deleteOnExit();
                }
            }
        }
        return new TpmQuote(System.currentTimeMillis(), pcrBanks, quoteData);
    }

    @Override
    public String getTpmVersion() {
        return "1.2";
    }

    /**
     *
     * @param ownerAuth
     * @return
     * @throws IOException
     */
    @Override
    public boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException {
        try {
            return getEndorsementKeyModulus(ownerAuth) != null;
        } catch (Tpm.TpmException e) {
            return false;
        }
    }

    /**
     *
     * @return @throws IOException
     * @throws TpmException
     */
    @Override
    public String getModuleLog() throws IOException, Tpm.TpmException {
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
                    LOG.debug("Error running command [{}]: {}", command.getExecutable(), result.getStandardError());
                    throw new Tpm.TpmException("TpmLinux.getModuleLog module_analysis.sh returned nonzero error", result.getReturnCode());
                }
                LOG.debug("command stdout: {}", result.getStandardOut());
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

    private String tcbMeasurementPath;

    /**
     * Sets the of the Tcb Measurement so it can be easily retrieved with {@link #getTcbMeasurement()
     * } down the line.
     *
     * @param path
     */
    public void setTcbMeasurementPath(String path) {
        tcbMeasurementPath = path;
    }

    /**
     *
     * @return @throws IOException
     * @throws TpmException
     */
    @Override
    public String getTcbMeasurement() throws IOException, Tpm.TpmException {
        File tcbMeasurementFile = Paths.get("/opt", "trustagent", "var", "measureLog.xml").toFile();
        if (tcbMeasurementFile.exists()) {
            return FileUtils.readFileToString(tcbMeasurementFile, Charset.forName("UTF-8"));
        } else {
            LOG.debug("TpmLinux.getTcbMeasurement measurement.xml does not exist");
            throw new Tpm.TpmTcbMeasurementMissingException("TpmLinux.getTcbMeasurement measurement.xml does not exist");
        }
    }
}
