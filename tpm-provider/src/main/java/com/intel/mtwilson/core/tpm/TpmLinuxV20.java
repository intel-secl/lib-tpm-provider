/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.CertifiedKey;
import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import com.intel.mtwilson.core.tpm.util.NvAttributeMapper;
import com.intel.mtwilson.core.tpm.util.PcrBanksMapper;
import com.intel.mtwilson.core.tpm.util.Utils;
import com.intel.mtwilson.core.tpm.util.Utils.SymCaDecryptionException;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import gov.niarl.his.privacyca.TpmUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import tss.TpmDeviceBase;
import tss.TpmDeviceLinux;
import tss.tpm.*;

/**
 *
 * @author dczech
 */
class TpmLinuxV20 extends TpmLinux {

    private final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TpmLinuxV20.class);

    tss.Tpm tpmNew;

    TpmLinuxV20() {
        super();
    }

    TpmLinuxV20(String tpmToolsPath) {
        super(tpmToolsPath);
        TpmDeviceBase base = new TpmDeviceLinux();
        tpmNew = new tss.Tpm();
        tpmNew._setDevice(base);
    }

    private void changeAuth(byte[] ownerAuth) throws IOException, TpmException {
        tpmNew.HierarchyChangeAuth(TPM_HANDLE.from(TPM_RH.OWNER), ownerAuth);
        tpmNew.HierarchyChangeAuth(TPM_HANDLE.from(TPM_RH.ENDORSEMENT), ownerAuth);
        tpmNew.HierarchyChangeAuth(TPM_HANDLE.from(TPM_RH.LOCKOUT), ownerAuth);
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, Tpm.TpmException {
        changeAuth(newOwnerAuth);

        TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.decrypt,
                        TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                        new TPMS_NULL_ASYM_SCHEME(),2048,0),
                new TPM2B_PUBLIC_KEY_RSA());
        CreatePrimaryResponse response = tpmNew.CreatePrimary(TPM_HANDLE.from(TPM_RH.OWNER),
                new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);

        byte[] persistent = new byte[] { (byte) 0x81, 0x00, 0x00, 0x00 };
        tpmNew.EvictControl(TPM_HANDLE.from(TPM_RH.OWNER), response.handle,
                TPM_HANDLE.fromTpm(persistent));
    }

    @Override
    public byte[] getCredential(byte[] ownerAuth, Tpm.CredentialType credentialType) throws IOException, Tpm.TpmException {
        if (credentialType != Tpm.CredentialType.EC) {
            throw new UnsupportedOperationException("TpmLinuxV20.getCredential Credential Types other than EC (Endorsement Credential) are not yet supported");
        }
        // WARNING HACK CODE HERE
        if(nvIndexExists(getECIndex()) && nvIndexExists(getECIndex()+1)) {
            byte[] part1 = nvRead(ownerAuth, getECIndex(), nvIndexSize(getECIndex()));
            byte[] part2 = nvRead(ownerAuth, getECIndex()+1, nvIndexSize(getECIndex()+1));
            return TpmUtils.concat(part1, part2);
        } else {
            LOG.debug("TpmLinuxV20.getCredential requested credential doesn't exist");
            throw new Tpm.TpmCredentialMissingException("TpmLinuxV20.getCredential requested credential doesn't exist");
        }
    }

    @Override
    public void setCredential(byte[] ownerAuth, Tpm.CredentialType credentialType, byte[] credentialBlob) throws IOException, Tpm.TpmException {
        if(credentialType != CredentialType.EC) {
            throw new UnsupportedOperationException("TpmLinuxV20.setCredential only CredentialType.EC is supported");
        }
        // WARNING!!!!! REALLY AWKARD CODE BELOW. TPM2_NVWRITE HAS A BUG. PLEASE RESOLVE ASAP
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
        nvDefine(ownerAuth, ownerAuth, getECIndex(), part1, NVAttribute.AUTHREAD, NVAttribute.OWNERWRITE, NVAttribute.OWNERREAD);
        byte[] part1Buf = Arrays.copyOfRange(credentialBlob, 0, part1);
        byte[] part2Buf = Arrays.copyOfRange(credentialBlob, part1, credentialBlob.length);
        nvWrite(ownerAuth, getECIndex(), part1Buf);
        nvDefine(ownerAuth, ownerAuth, getECIndex() + 1, part2, NVAttribute.AUTHREAD, NVAttribute.OWNERWRITE, NVAttribute.OWNERREAD);
        nvWrite(ownerAuth, getECIndex()+1, part2Buf);
    }

    private int findKeyHandle(String mask) throws Tpm.TpmException, IOException {
        TpmTool listPersistent = new TpmTool(getTpmToolsPath(), ("tpm2_listpersistent"));
        CommandLineResult result = listPersistent.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.findKey tpm2_listpersistent returned nonzero error {}", result.getReturnCode());
            throw new Tpm.TpmException("TpmLinuxV20.findKey tpm2_listpersistent returned nonzero error", result.getReturnCode());
        }
        Pattern p = Pattern.compile(mask);
        Matcher m = p.matcher(result.getStandardOut());
        if (m.find()) {
            return Long.decode(m.group()).intValue();
        }
        return 0;
    }

    private int findAikHandle() throws Tpm.TpmException, IOException {
        for (int i = 0x81018; i < 0x81020; i++) {
            int index = findKeyHandle(String.format("0x%05x...", i));
            if (index != 0) {
                return index;
            }
        }
        throw new Tpm.TpmException("TpmLinuxV20.findAk could not find Ak");
    }

    private int findEkHandle() throws IOException, Tpm.TpmException {
        int index = findKeyHandle("0x810100..");
        if (index != 0) {
            return index;
        } else {
            throw new Tpm.TpmException("TpmLinuxV20.findEk could not find Ek");
        }
    }

    private int getNextUsableHandle() throws Tpm.TpmException, IOException {
        TpmTool listPersistent = new TpmTool(getTpmToolsPath(), ("tpm2_listpersistent"));
        CommandLineResult result = listPersistent.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.getNextUsableHandle tpm2_listpersistent returned nonzero error {}", result.getReturnCode());
            throw new Tpm.TpmException("TpmLinuxV20.getNextUsableHandle tpm2_listpersistent returned nonzero error", result.getReturnCode());
        }
        int index = 0x81010000;
        for (int i = 0; i <= 255; i++) {
            if (!result.getStandardOut().contains(String.format("0x%08x", index + i))) {
                return index + i;
            }
        }
        throw new Tpm.TpmException("TpmLinuxV20.getNextUsableHandle no usable persistent handles are available");
    }

    private int createEk(byte[] ownerAuth, byte[] endorsePass) throws Tpm.TpmException, IOException {
        int ekHandle = getNextUsableHandle();
        File ekFile = Utils.getTempFile("endorsementkey", "tmp");
        TpmTool getPubEk = new TpmTool(getTpmToolsPath(), ("tpm2_getpubek"));
        getPubEk.addArgument("-e");
        getPubEk.addArgument("${endorsePass}");
        getPubEk.addArgument("-o");
        getPubEk.addArgument("${ownerPass}");
        getPubEk.addArgument("-H");
        getPubEk.addArgument("${ekHandle}");
        getPubEk.addArgument("-g");
        getPubEk.addArgument("0x1");
        getPubEk.addArgument("-f");
        getPubEk.addArgument("${ekFile}");
        Map<String, Object> subMap = new HashMap<>();
        subMap.put("endorsePass", "hex:" + TpmUtils.byteArrayToHexString(endorsePass));
        subMap.put("ownerPass", "hex:" + TpmUtils.byteArrayToHexString(ownerAuth));
        subMap.put("ekHandle", String.format("0x%08x", ekHandle));
        subMap.put("ekFile", ekFile);
        getPubEk.setSubstitutionMap(subMap);
        CommandLineResult result = getPubEk.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.createEk tpm2_getpubek returned nonzero error {}", result.getReturnCode());
            throw new Tpm.TpmException("TpmLinuxV20.createEk tpm2_getpubek returned nonzero error", result.getReturnCode());
        }
        return ekHandle;
    }

    private int findOrCreateEk(byte[] ownerAuth, byte[] endorseAuth) throws Tpm.TpmException, IOException {
        try {
            return findEkHandle();
        } catch (Tpm.TpmException te) {
            return createEk(ownerAuth, endorseAuth);
        }
    }

    private void clearAkHandle(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        TpmTool listPersistent = new TpmTool(getTpmToolsPath(), ("tpm2_listpersistent"));
        CommandLineResult result = listPersistent.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.clearAkHandle tpm2_listpersistent returned nonzero errro {}", result.getReturnCode());
            throw new Tpm.TpmException("TpmLinuxV20.clearAkHandle tpm2_listpersistent returned nonzero error", result.getReturnCode());
        }
        if (result.getStandardOut().contains("0x81018000")) {
            TpmTool evictControl = new TpmTool(getTpmToolsPath(), ("tpm2_evictcontrol"));
            evictControl.addArgument("-A");
            evictControl.addArgument("o");
            evictControl.addArgument("-H");
            evictControl.addArgument("${aikHandle}");
            evictControl.addArgument("-S");
            evictControl.addArgument("${otherHandle}");
            evictControl.addArgument("-P");
            evictControl.addArgument("${ownerPass}");
            Map<String, Object> subMap = new HashMap<>();
            subMap.put("aikHandle", "0x81018000");
            subMap.put("otherHandle", "0x81018000");
            subMap.put("ownerPass", "hex:" + TpmUtils.byteArrayToHexString(ownerAuth));
            evictControl.setSubstitutionMap(subMap);
            result = evictControl.execute();
            if (result.getReturnCode() != 0) {
                LOG.debug("TpmLinuxV20.clearAkHandle tpm2_evictcontrol returned nonzero error {}", result.getReturnCode());
                throw new Tpm.TpmException("TpmLinuxV20.clearAkHandle tpm2_evictcontrol returned nonzero error", result.getReturnCode());
            }
        }
    }

    @Override
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);
        File ekFile = Utils.getTempFile("endorsementkey", "pub");
        TpmTool readPublic = new TpmTool(getTpmToolsPath(), ("tpm2_readpublic"));
        readPublic.addArgument("-H");
        readPublic.addArgument("${ekHandle}");
        readPublic.addArgument("-o");
        readPublic.addArgument("${ekFile}");
        Map<String, Object> subMap = new HashMap<>();
        subMap.put("ekHandle", String.format("0x%08x", ekHandle));
        subMap.put("ekFile", ekFile);
        readPublic.setSubstitutionMap(subMap);
        CommandLineResult result = readPublic.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.getEndorsementKeyModulus failed to read public key");
            throw new Tpm.TpmException("TpmLinuxV20.getEndorsementKeyModulus failed to read public key");
        }
        byte[] ekMod = FileUtils.readFileToByteArray(ekFile);
        ekFile.delete();
        return Arrays.copyOfRange(ekMod, 60, 256 + 60);
    }
    
    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, Tpm.TpmException, CertificateEncodingException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);
        LOG.info("TpmLinuxV20.collateIdentityRequest using EkHandle: {}", String.format("0x%08x", ekHandle));
        // existing akHandle so we can use it
        clearAkHandle(ownerAuth);
        File aikFile = Utils.getTempFile("aik", "tmp");
        File aikNameFile = Utils.getTempFile("aikname", "tmp");
        TpmTool tool = new TpmTool(getTpmToolsPath(), ("tpm2_getpubak"));
        tool.addArgument("-e");
        tool.addArgument("${endorsePass}");
        tool.addArgument("-o");
        tool.addArgument("${ownerPass}");
        tool.addArgument("-P");
        tool.addArgument("${aikPass}");
        tool.addArgument("-E");
        tool.addArgument("${ekHandle}");
        tool.addArgument("-k");
        tool.addArgument("${aikHandle}");
        tool.addArgument("-f");
        tool.addArgument("${aikFile}");
        tool.addArgument("-n");
        tool.addArgument("${aikNameFile}");
        tool.addArgument("-g");
        tool.addArgument("${aikTypeHex}");
        tool.addArgument("-D");
        tool.addArgument("0x000B");
        tool.addArgument("-s");
        tool.addArgument("0x0014");
        Map<String, Object> subMap = new HashMap<>();
        subMap.put("endorsePass", "hex:" + TpmUtils.byteArrayToHexString(ownerAuth));
        subMap.put("ownerPass", "hex:" + TpmUtils.byteArrayToHexString(ownerAuth));
        subMap.put("aikPass", "hex:" + TpmUtils.byteArrayToHexString(keyAuth));
        subMap.put("ekHandle", String.format("0x%08x", ekHandle));
        subMap.put("aikHandle", "0x81018000");
        subMap.put("aikFile", aikFile);
        subMap.put("aikNameFile", aikNameFile);
        subMap.put("aikTypeHex", Tpm.EncryptionAlgorithm.RSA.toHex());
        tool.setSubstitutionMap(subMap);
        CommandLineResult result = tool.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmModule20.collateIdentityRequest returned nonzero error {} stderr {}", result.getReturnCode(), result.getStandardError());
            throw new Tpm.TpmException("TpmModule20.collateIdentityRequest returned nonzero error", result.getReturnCode());
        }
        LOG.debug("TpmLinuxV20.collateIdentityRequest debugdebugAIK handle: {}", "0x81018000");
        // currenlty we don't export the entire AIK blob, since its persisted on the TPM, and we access it through a handle. 
        // For TPM2.0 we can just return the handle instead of the actual blob, and achieve the same effect
        byte[] aikHandle = Utils.intToByteArray(0x81018000);
        byte[] credRequest = FileUtils.readFileToByteArray(aikFile);
        credRequest = Arrays.copyOfRange(credRequest, 26, 256 + 26);
        byte[] aikName = FileUtils.readFileToByteArray(aikNameFile);
        LOG.debug("AIK pub key: {}", TpmUtils.byteArrayToHexString(credRequest));
        LOG.debug("AIK name: {}", TpmUtils.byteArrayToHexString(aikName));
        // TPM 2.0 identityRequest and aikpub are used as the same
        IdentityRequest newId = new IdentityRequest(this.getTpmVersion(), credRequest, credRequest, aikHandle, aikName);
        return newId;
    }

    @Override
    public byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest)
            throws IOException, Tpm.TpmException {
        int akHandle = findAikHandle();
        int ekHandle = findEkHandle();
        LOG.debug(" AIK Handle : {}", akHandle);
        LOG.debug(" AIK Handle : {}", String.format("0x%08x", akHandle));
        LOG.debug(" EK Handle : {}", ekHandle);
        LOG.debug(" EK Handle : {}", String.format("0x%08x", ekHandle));
        File credentialBlobFile = Utils.getTempFile("mkcredential", "out");
        File decryptedCred = Utils.getTempFile("decrypted", "out");

        FileUtils.writeByteArrayToFile(credentialBlobFile, TpmUtils.concat(TpmUtils.concat(proofRequest.getHeader(),
                proofRequest.getCredential()), proofRequest.getSecret()));
        TpmTool activateCredential = new TpmTool(getTpmToolsPath(), ("tpm2_activatecredential"));
        activateCredential.addArgument("-e");
        activateCredential.addArgument("${ownerPass}");
        activateCredential.addArgument("-P");
        activateCredential.addArgument("${aikAuth}");
        activateCredential.addArgument("-H");
        activateCredential.addArgument("${akHandle}");
        activateCredential.addArgument("-k");
        activateCredential.addArgument("${ekHandle}");
        activateCredential.addArgument("-f");
        activateCredential.addArgument("${credentialBlobFile}");
        activateCredential.addArgument("-o");
        activateCredential.addArgument("${decryptedCred}");
        Map<String, Object> subMap = new HashMap<>();
        subMap.put("ownerPass", "hex:" + TpmUtils.byteArrayToHexString(ownerAuth));
        subMap.put("aikAuth", "hex:" + TpmUtils.byteArrayToHexString(keyAuth));
        subMap.put("akHandle", String.format("0x%08x", akHandle));
        subMap.put("ekHandle", String.format("0x%08x", ekHandle));
        subMap.put("credentialBlobFile", credentialBlobFile);
        subMap.put("decryptedCred", decryptedCred);
        activateCredential.setSubstitutionMap(subMap);
        CommandLineResult result = activateCredential.execute();
        if (result.getReturnCode() != 0) {
            throw new Tpm.TpmException("Tpm2 activatecredential returned non zero error");
        }
        byte[] decrypted = FileUtils.readFileToByteArray(decryptedCred);
        try {
            return Utils.decryptSymCaAttestation(decrypted, proofRequest.getSymBlob());
        } catch (BufferUnderflowException | SymCaDecryptionException ex) {
            LOG.debug("TpmLinuxV20.activateIdentity failed with exception", ex);
            throw new Tpm.TpmException("TpmLinuxV20.activateIdentity failed with exception", ex);
        }
    }

    @Override
    public CertifiedKey createAndCertifyKey(Tpm.KeyType keyType, byte[] keyAuth, byte[] aikAuth) throws IOException, Tpm.TpmException {
        final String srkHandle = "0x81000000";
        File publicFile = Utils.getTempFile("out", "pub");
        File privateFile = Utils.getTempFile("out", "priv");
        TpmTool create = new TpmTool(getTpmToolsPath(), ("tpm2_create"));
        create.addArgument("-H");
        create.addArgument("${handle}");
        create.addArgument("-g");
        create.addArgument("${hashTypeHex}");
        create.addArgument("-G");
        create.addArgument("${encTypeHex}");
        create.addArgument("-A");
        create.addArgument("${attr}");
        create.addArgument("-u");
        create.addArgument("${outpub}");
        create.addArgument("-r");
        create.addArgument("${outpriv}");
        Map<String, Object> subMap = new HashMap<>();
        subMap.put("handle", srkHandle); // SRK handle
        subMap.put("hashTypeHex", Tpm.PcrBank.SHA256.toHex());
        subMap.put("encTypeHex", Tpm.EncryptionAlgorithm.RSA.toHex());
        String attr;
        switch (keyType) {
            case BIND:
                attr = "0x00020072";
                break;
            case SIGN:
                attr = "0x00040072";
                break;
            default:
                LOG.debug("TpmLinuxV20.createAndCertifyKey keyType is not BIND or SIGN");
                throw new IllegalArgumentException("TpmLinuxV20.createAndCertifyKey keyType is not BIND or SIGN");
        }
        subMap.put("attr", attr);
        subMap.put("outpub", publicFile);
        subMap.put("outpriv", privateFile);
        create.setSubstitutionMap(subMap);
        CommandLineResult result = create.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.createAndCertifyKey tpm2_load returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV20.createAndCertify key tpm2_load returned nonzero error", result.getReturnCode());
        }
        File context = Utils.getTempFile("object", "context");
        File outfilename = Utils.getTempFile("outfilename", "tmp");
        File attestFile = Utils.getTempFile("out", "attest");
        File sigFile = Utils.getTempFile("out", "sig");
        TpmTool load = new TpmTool(getTpmToolsPath(), ("tpm2_load"));
        load.addArgument("-H");
        load.addArgument("${parentHandle}");
        load.addArgument("-u");
        load.addArgument("${inpub}");
        load.addArgument("-r");
        load.addArgument("${inpriv}");
        load.addArgument("-C");
        load.addArgument("${context}");
        load.addArgument("-n");
        load.addArgument("${outfilename}");
        subMap.clear();
        subMap.put("parentHandle", srkHandle);
        subMap.put("inpub", publicFile);
        subMap.put("inpriv", privateFile);
        subMap.put("context", context);
        subMap.put("outfilename", outfilename);
        load.setSubstitutionMap(subMap);
        result = load.execute();
        if (result.getReturnCode() != 0) {
            // throw
            LOG.debug("TpmLinuxV20.createAndCertifyKey tpm2_load returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV20.createAndCertify key tpm2_load returned nonzero error", result.getReturnCode());
        }
        TpmTool certify = new TpmTool(getTpmToolsPath(), ("tpm2_certify"));
        certify.addArgument("-k");
        certify.addArgument("${signingHandle}");
        certify.addArgument("-K");
        certify.addArgument("${signingPass}");
        certify.addArgument("-g");
        certify.addArgument("${hashAlgHex}");
        certify.addArgument("-a");
        certify.addArgument("${outAttest}");
        certify.addArgument("-s");
        certify.addArgument("${outSig}");
        certify.addArgument("-C");
        certify.addArgument("${context}");
        subMap.clear();
        subMap.put("signingHandle", String.format("0x%08x", findAikHandle()));
        subMap.put("signingPass", "hex:" + TpmUtils.byteArrayToHexString(aikAuth));
        subMap.put("hashAlgHex", Tpm.PcrBank.SHA256.toHex());
        subMap.put("outAttest", attestFile);
        subMap.put("outSig", sigFile);
        subMap.put("context", context);
        certify.setSubstitutionMap(subMap);
        result = certify.execute();
        if (result.getReturnCode() != 0) {
            LOG.debug("TpmLinuxV20.createAndCertifyKey tpm2_certify returned nonzero error {}", result.getReturnCode());
            throw new TpmException("TpmLinuxV20.createAndCertifyKey tpm2_certify returned nonzero error", result.getReturnCode());
        }
        CertifiedKey key = new CertifiedKey();
        key.setKeyModulus(FileUtils.readFileToByteArray(publicFile));
        key.setKeyBlob(FileUtils.readFileToByteArray(privateFile));
        key.setKeyData(FileUtils.readFileToByteArray(attestFile));
        key.setKeySignature(FileUtils.readFileToByteArray(sigFile));
        key.setKeyName(FileUtils.readFileToByteArray(outfilename));
        // Everything went well, delete the temporary files, otherwise leave them for debugging (they are always unique anyway)
        privateFile.delete();
        publicFile.delete();
        context.delete();
        outfilename.delete();
        attestFile.delete();
        sigFile.delete();
        return key;
    }

    @Override
    public void setAssetTag(byte[] ownerAuth, byte[] assetTagHash) throws IOException, Tpm.TpmException {
        int index = getAssetTagIndex();
        if (nvIndexExists(index)) {
            LOG.debug("TpmLinuxV20.setAssetTag index {} already exists. Releasing index...", index);
            nvRelease(ownerAuth, index);
            LOG.debug("TpmLinuxV20.setAssetTag creating new index...");
        } else {
            LOG.debug("TpmLinuxV20.setAssetTag index does not exist, creating it...");
        }
        nvDefine(ownerAuth, ownerAuth, index, 32, NVAttribute.AUTHREAD, NVAttribute.OWNERWRITE, NVAttribute.OWNERREAD);

        nvWrite(ownerAuth, index, assetTagHash);
        LOG.debug("TpmLinuxV20.setAssetTag successfully provisioned asset tag");
    }

    @Override
    public byte[] readAssetTag(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        int index = getAssetTagIndex();
        LOG.debug("TpmLinuxV20.readAssetTag reading asset tag at index {}", index);
        if (nvIndexExists(index)) {
            LOG.debug("TpmLinuxV20.readAssetTag index {} exists", index);
            return nvRead(ownerAuth, index, 32);
        } else {
            throw new Tpm.TpmException("TpmLinuxV20.readAssetTag asset tag has not been provisioned on this TPM");
        }
    }

    @Override
    public int getAssetTagIndex() {
        return 0x1c10110;
    }

    private int getECIndex() {
        return 0x01c00000;
    }

    @Override
    public Set<Tpm.PcrBank> getPcrBanks() throws IOException, Tpm.TpmException {
        GetCapabilityResponse caps = tpmNew.GetCapability(TPM_CAP.ALGS, 0, TPM_ALG_ID.values().size());
        TPML_ALG_PROPERTY algs = (TPML_ALG_PROPERTY) (caps.capabilityData);
        Set<Tpm.PcrBank> pcrBanks = EnumSet.allOf(Tpm.PcrBank.class);
        Set<Tpm.PcrBank> supportedPcrBanks = EnumSet.noneOf(Tpm.PcrBank.class);
        for(Tpm.PcrBank bank : pcrBanks) {
            for (TPMS_ALG_PROPERTY p : algs.algProperties) {
                if(p.alg.name().equalsIgnoreCase(bank.name())) {
                    supportedPcrBanks.add(bank);
                }
            }
        }
        if (supportedPcrBanks.isEmpty()) {
            LOG.debug("TpmLinuxV20.getPcrBanks failed to retrieve list of PCR banks");
            throw new Tpm.TpmException("TpmLinuxV20.getPcrBanks failed to retrieve list of PCR Banks");
        }
        return supportedPcrBanks;
    }

    @Override
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<NVAttribute> attributes) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        nvHandle.AuthValue = indexPassword;
        TPM_ALG_ID algorithm = TPM_ALG_ID.SHA256;
        TPMA_NV nvAttributes = getTpmaNvFromAttributes(attributes);
        byte[] authPolicy = new byte[0];
        TPMS_NV_PUBLIC nvPub = new TPMS_NV_PUBLIC(nvHandle, algorithm, nvAttributes, authPolicy, size);
        try {
            tpmNew.NV_DefineSpace(ownerHandle, ownerAuth, nvPub);
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("succeeded")) {
                LOG.debug("TpmLinuxV20.nvDefine returned error {}", e.getMessage());
                throw new Tpm.TpmException("TpmLinuxV20.nvDefine returned error", e);
            }
        }
    }

    private TPMA_NV getTpmaNvFromAttributes(Set<NVAttribute> attributes) {
        List<TPMA_NV> nvAttributeList = new ArrayList<>();
        for(NVAttribute attr : attributes) {
            nvAttributeList.add(NvAttributeMapper.getMappedNvAttribute(attr));
        }
        return new TPMA_NV(nvAttributeList.toArray(new TPMA_NV[nvAttributeList.size()]));
    }


    @Override
    public void nvRelease(byte[] ownerAuth, int index) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        TPM_HANDLE nvIndex = new TPM_HANDLE(index);
        tpmNew._allowErrors().NV_UndefineSpace(ownerHandle, nvIndex);
    }

    @Override
    public byte[] nvRead(byte[] authPassword, int index, int size) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = authPassword;
        TPM_HANDLE nvIndex = new TPM_HANDLE(index);
        nvIndex.AuthValue = authPassword;
        return tpmNew.NV_Read(ownerHandle, nvIndex,  size,  0);
    }

    @Override
    public void nvWrite(byte[] authPassword, int index, byte[] data) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = authPassword;
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        nvHandle.AuthValue = authPassword;
        tpmNew.NV_Write(ownerHandle, nvHandle, data,  0);
    }

    @Override
    public boolean nvIndexExists(int index) throws IOException, Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        NV_ReadPublicResponse nvPub;
        try {
            nvPub = tpmNew.NV_ReadPublic(nvHandle);
        } catch (tss.TpmException e) {
            if(e.getMessage().contains("HANDLE")) {
                return false;
            } else {
                LOG.debug("TpmLinuxV20.nvIndexExists could not find NV index {}", String.format("0x%08x", index));
                throw new TpmException("TpmLinuxV20.nvIndexExists could not find NV index " + String.format("0x%08x", index));
            }
        }
        return index == nvPub.nvPublic.nvIndex.handle;
    }

    @Override
    public TpmQuote getQuote(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs, byte[] aikBlob, byte[] aikAuth, byte[] nonce)
            throws IOException, Tpm.TpmException {
        byte[] pcrsResult = getPcrs(pcrBanks, pcrs);
        System.out.println("Pcr List from code - " + TpmUtils.byteArrayToHexString(pcrsResult));

        TPMS_PCR_SELECTION[] selectedPcrsToQuote = getTpmsPcrToQuoteSelections(pcrBanks, pcrs);
        TPM_HANDLE handle = TPM_HANDLE.from(ByteBuffer.wrap(aikBlob).order(ByteOrder.BIG_ENDIAN).getInt());
        handle.AuthValue = aikAuth;
        QuoteResponse quote = tpmNew.Quote(handle, nonce, new TPMS_NULL_SIG_SCHEME(), selectedPcrsToQuote);
        System.out.println("--------------- Quote ------------ \n  " +  quote.toString());

        // Validate the quote using tss.Java support functions
        TPM_HANDLE ekhandle = new TPM_HANDLE(findEkHandle());
        ekhandle.AuthValue = aikAuth;
        ReadPublicResponse aikPub = tpmNew.ReadPublic(ekhandle);
        boolean signOk = aikPub.outPublic.validateSignature(nonce, new TPMS_NULL_SIG_SCHEME());
        System.out.println("Sign validated:" + signOk);

        //boolean quoteOk = aikPub.outPublic.validateQuote(pcrsNew, nonce, quote);
        //System.out.println("Quote validated:" + quoteOk);
        /*
        // first convert the Java arguments into string form to pass into tpm2_listpcrs and then tpm2_quote
        String quoteAlgWithPcrs;
        List<String> bankList = new ArrayList<>();
        pcrBanks.forEach((bank) -> {
            String selectedPcrList = pcrs.stream().map(Pcr::toInt).sorted().map(pcr -> Integer.toString(pcr)).collect(Collectors.joining(","));
            bankList.add(bank.toHex() + ":" + selectedPcrList);
        });
        quoteAlgWithPcrs = StringUtils.join(bankList, '+');
        File tempPcrsFile = Utils.getTempFile("pcrs", "tmp");
        TpmTool pcrList = new TpmTool(getTpmToolsPath(), ("tpm2_pcrlist"));
        pcrList.addArgument("-L");
        pcrList.addArgument("${pcrs}");
        pcrList.addArgument("-o");
        pcrList.addArgument("${file}");
        Map<String, Object> subMap = new HashMap<>();
        subMap.put("pcrs", quoteAlgWithPcrs);
        subMap.put("file", tempPcrsFile);
        pcrList.setSubstitutionMap(subMap);
        // execute tpm2_pcrlist
        CommandLineResult result = pcrList.execute();
        if (result.getReturnCode() != 0) {
            throw new Tpm.TpmException("TpmLinuxV20.getQuote tpm2_listpcrs failed", result.getReturnCode());
        }
        // now we move to tpm2_quote, create some temporary files to store the output
        File tempMessageFile = Utils.getTempFile("quote", "tmp");
        File tempSigFile = Utils.getTempFile("quote_sig", "tmp");
        int aikHandle = ByteBuffer.wrap(aikBlob).order(ByteOrder.BIG_ENDIAN).getInt();
        TpmTool tpmQuote = new TpmTool(getTpmToolsPath(), ("tpm2_quote"));
        tpmQuote.addArgument("-k");
        tpmQuote.addArgument("${aikHandle}");
        tpmQuote.addArgument("-P");
        tpmQuote.addArgument("${aikAuth}");
        tpmQuote.addArgument("-L");
        tpmQuote.addArgument("${quoteAlg}");
        tpmQuote.addArgument("-q");
        tpmQuote.addArgument("${nonce}");
        tpmQuote.addArgument("-m");
        tpmQuote.addArgument("${messageFile}");
        tpmQuote.addArgument("-s");
        tpmQuote.addArgument("${sigFile}");
        tpmQuote.addArgument("-f");
        tpmQuote.addArgument("${format}");
        subMap = new HashMap<>();
        subMap.put("aikHandle", String.format("0x%08x", aikHandle));
        subMap.put("aikAuth", "hex:" + TpmUtils.byteArrayToHexString(aikAuth));
        subMap.put("quoteAlg", quoteAlgWithPcrs);
        subMap.put("nonce", TpmUtils.byteArrayToHexString(nonce));
        subMap.put("messageFile", tempMessageFile);
        subMap.put("sigFile", tempSigFile);
        subMap.put("format", "plain");
        tpmQuote.setSubstitutionMap(subMap);
        result = tpmQuote.execute();
        if (result.getReturnCode() != 0) {
            throw new Tpm.TpmException("TpmLinuxV20.getQuote tpm2_quote failed", result.getReturnCode());
        }
        byte[] pcrsResult = Files.readAllBytes(tempPcrsFile.toPath());
        byte[] messageResult = Files.readAllBytes(tempMessageFile.toPath());
        byte[] sigResult = Files.readAllBytes(tempSigFile.toPath());
        int SHORT_BYTES = 2;
        File sigOFile = Utils.getTempFile("quote_old_sign", "temp");
        FileUtils.writeByteArrayToFile(sigOFile, sigResult);
        File msgFile = Utils.getTempFile("quote_msg", "temp");
        FileUtils.writeByteArrayToFile(msgFile, messageResult);

        sigResult = marshalSig(sigResult);        
        File sigFile = Utils.getTempFile("quote_sign", "temp");
        FileUtils.writeByteArrayToFile(sigFile, sigResult);

        ByteBuffer quoteBlob = ByteBuffer.allocate((short)SHORT_BYTES + pcrsResult.length + messageResult.length + sigResult.length);
        quoteBlob.order(ByteOrder.LITTLE_ENDIAN).putShort((short) messageResult.length);
        quoteBlob.put(messageResult);
        quoteBlob.put(sigResult);
        quoteBlob.put(pcrsResult);

        File ekkPubFile = Utils.getTempFile("all_quote", "temp");
        FileUtils.writeByteArrayToFile(ekkPubFile, quoteBlob.array());
        
        tempPcrsFile.delete();
        tempQuoteFile.delete();*/
        byte[] combined = ArrayUtils.addAll(quote.toTpm(), pcrsResult);
        return new TpmQuote(System.currentTimeMillis(), pcrBanks, combined);
    }

    // As 'PCR_Read' does not result more than 8 PCR values, we need to read them in chunks
    private byte[] getPcrs(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) throws IOException {
        ByteArrayOutputStream pcrStream = new ByteArrayOutputStream();
        for(TPMS_PCR_SELECTION pcrSelection: getTpmsPcrSelections(pcrBanks, pcrs)) {
            PCR_ReadResponse pcrsNew = tpmNew.PCR_Read(new TPMS_PCR_SELECTION[]{pcrSelection});
            for(TPM2B_DIGEST digest : pcrsNew.pcrValues) {
                pcrStream.write(digest.buffer);
            }
        }
        return pcrStream.toByteArray();
    }

    private TPMS_PCR_SELECTION[] getTpmsPcrToQuoteSelections(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) {
        int[] pcrLists = pcrs.stream().map(Pcr::toInt).mapToInt(i->i).toArray();
        List<TPMS_PCR_SELECTION> selectedPcrs = new ArrayList<>();
        for(TPM_ALG_ID alg : PcrBanksMapper.getMappedPcrBanks(pcrBanks)) {
            selectedPcrs.add(new TPMS_PCR_SELECTION(alg, pcrLists));
        }
        return selectedPcrs.toArray(new TPMS_PCR_SELECTION[selectedPcrs.size()]);
    }

    private TPMS_PCR_SELECTION[] getTpmsPcrSelections(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) {
        int[] pcrLists = pcrs.stream().map(Pcr::toInt).mapToInt(i->i).toArray();
        List<TPMS_PCR_SELECTION> selectedPcrs = new ArrayList<>();
        for(TPM_ALG_ID alg : PcrBanksMapper.getMappedPcrBanks(pcrBanks)) {
            if(pcrLists.length < 8) {
                selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 0, pcrLists.length)));
            } else {
                if (pcrLists.length > 8) {
                    selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 0, 8)));
                }
                if (pcrLists.length > 16) {
                    selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 8, 16)));
                    selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 16, pcrLists.length)));
                }
            }
        }
        return selectedPcrs.toArray(new TPMS_PCR_SELECTION[selectedPcrs.size()]);
    }

    @Override
    public String getTpmVersion() {
        return "2.0";
    }

    private int nvIndexSize(int index) throws IOException, Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        NV_ReadPublicResponse nvPub;
        try {
            nvPub = tpmNew.NV_ReadPublic(nvHandle);
        } catch (Exception e) {
            LOG.debug("TpmLinuxV20.nvIndexSize could not find size of index {}", String.format("0x%08x", index));
            throw new TpmException("TpmLinuxV20.nvIndexSize could not find size of index " + String.format("0x%08x", index));
        }
        return nvPub.nvPublic.dataSize;
    }

    /**
     *
     * @param ownerAuth
     * @return
     * @throws IOException
     */
    @Override
    public boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException {
        TpmTool tool = new TpmTool(getTpmToolsPath(), "tpm2_takeownership");
        String auth = "hex:" + TpmUtils.byteArrayToHexString(ownerAuth);
        tool.addArgument("-o");
        tool.addArgument(auth);
        tool.addArgument("-e");
        tool.addArgument(auth);
        tool.addArgument("-l");
        tool.addArgument(auth);
        tool.addArgument("-O");
        tool.addArgument(auth);
        tool.addArgument("-E");
        tool.addArgument(auth);
        tool.addArgument("-L");
        tool.addArgument(auth);
        CommandLineResult result = tool.execute();
        return result.getReturnCode() == 0;
    }

}
