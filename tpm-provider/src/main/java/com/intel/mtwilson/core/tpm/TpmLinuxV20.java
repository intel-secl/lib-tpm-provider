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
import java.util.*;
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

    private boolean changeAuth(byte[] oldAuth, byte[] newAuth) {
        Set<TPM_HANDLE> handles = new HashSet<>(Arrays.asList(TPM_HANDLE.from(TPM_RH.OWNER),
                TPM_HANDLE.from(TPM_RH.ENDORSEMENT), TPM_HANDLE.from(TPM_RH.LOCKOUT)));

        for (TPM_HANDLE handle : handles) {
            if (oldAuth != null) {
                handle.AuthValue = oldAuth;
            }
            try {
                tpmNew.HierarchyChangeAuth(handle, newAuth);
            } catch (tss.TpmException e) {
                return false;
            }
        }

        return true;
    }

    private void changeAuth(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        if (!changeAuth(null, ownerAuth)) {
            byte[] newOwnerPass = TpmUtils.createRandomBytes(20);
            if (!changeAuth(ownerAuth, newOwnerPass)) {
                // supplied newOwnerAuth is invalid
                LOG.debug("TpmLinuxV20.takeAndCheckOwnership cannot take ownership; TPM claimed with a different password");
                throw new Tpm.TpmException("TpmLinuxV20.takeAndCheckOwnership cannot take ownership; TPM claimed with a different password");
            } else {
                if (!changeAuth(newOwnerPass, ownerAuth)) {
                    LOG.debug("TpmLinuxV20.takeAndCheckOwnership CRITICAL ERROR: Could not change TPM password back from temporary. TPM must be reset from bios");
                    throw new Tpm.TpmException("TpmLinuxV20.takeAndCheckOwnership CRITICAL ERROR: "
                            + "Could not change TPM password back from temporary. TPM must be reset from bios");
                }
            }
        }
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

        CreatePrimaryResponse cpResponse;
        //try {
            cpResponse = tpmNew.CreatePrimary(TPM_HANDLE.from(TPM_RH.OWNER),
                    new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
        /*} catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.takeOwnership failed to create storage primary key");
            throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to create storage primary key");
        }*/
        System.out.println("create primary response : " + cpResponse.toString());

        byte[] persistent = new byte[] { (byte) 0x81, 0x00, 0x00, 0x00 };
        TPM_HANDLE ohandle = TPM_HANDLE.fromTpm(persistent);
        ohandle.AuthValue = newOwnerAuth;
        //try {
            tpmNew.EvictControl(TPM_HANDLE.from(TPM_RH.OWNER), cpResponse.handle,
                    ohandle);
        /*} catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
            throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
        }*/
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
        GetCapabilityResponse gcResponse = tpmNew.GetCapability(TPM_CAP.HANDLES, TPM_HT.PERSISTENT.toInt() << 24, 16);
        TPML_HANDLE handles = (TPML_HANDLE) gcResponse.capabilityData;
        System.out.println(handles.handle.length + " persistent objects defined.");

        Pattern p = Pattern.compile(mask);
        Matcher m;
        for (int i = 0; i < handles.handle.length; i++) {
            System.out.println(i + ". Persistent handle: " + handles.handle[i].toString());
            m = p.matcher(handles.handle[i].toString());
            if (m.find()) {
                return Long.decode(m.group()).intValue();
            }
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
        GetCapabilityResponse gcResponse = tpmNew.GetCapability(TPM_CAP.HANDLES, TPM_HT.PERSISTENT.toInt() << 24, 16);
        TPML_HANDLE handles = (TPML_HANDLE) gcResponse.capabilityData;
        System.out.println(handles.handle.length + " persistent objects defined.");

        int index = 0x81010000;
        int count;
        for (int j = 0; j <= 255; j++) {
            count = 0;
            for (int i = 0; i < handles.handle.length; i++) {
                System.out.println(i + ". Persistent handle: " + handles.handle[i].toString());
                if (!handles.handle[i].toString().contains(String.format("0x%08x", index + j))) {
                    count++;
                }
            }
            if (count == handles.handle.length) {
                return index + j;
            }
        }
        throw new Tpm.TpmException("TpmLinuxV20.getNextUsableHandle no usable persistent handles are available");
    }

    private int createEk(byte[] ownerAuth, byte[] endorsePass) throws Tpm.TpmException, IOException {
        int ekHandle = getNextUsableHandle();
        System.out.println("ekHandle : " + String.format("0x%08x", ekHandle));

        byte auth_policy[] = {
                (byte)0x83, 0x71, (byte)0x97, 0x67, 0x44, (byte)0x84, (byte)0xB3, (byte)0xF8, 0x1A, (byte)0x90, (byte)0xCC,
                (byte)0x8D, 0x46, (byte)0xA5, (byte)0xD7, 0x24, (byte)0xFD, 0x52, (byte)0xD7, 0x6E, 0x06, 0x52,
                0x0B, 0x64, (byte)0xF2, (byte)0xA1, (byte)0xDA, 0x1B, 0x33, 0x14, 0x69, (byte)0xAA
        };

        TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.adminWithPolicy, TPMA_OBJECT.decrypt,
                        TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                auth_policy,
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                        new TPMS_NULL_ASYM_SCHEME(),2048,0),
                new TPM2B_PUBLIC_KEY_RSA());

        TPM_HANDLE handle;
        CreatePrimaryResponse cpResponse;
        handle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
        handle.AuthValue = endorsePass;
        //try {
        cpResponse = tpmNew.CreatePrimary(handle,
                new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
        /*} catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.takeOwnership failed to create storage primary key");
            throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to create storage primary key");
        }*/
        System.out.println("create primary response: " + cpResponse.toString());

        handle = TPM_HANDLE.from(TPM_RH.OWNER);
        handle.AuthValue = ownerAuth;
        TPM_HANDLE ehandle = TPM_HANDLE.from(ekHandle);
        ehandle.AuthValue = endorsePass;
        //try {
        tpmNew.EvictControl(handle, cpResponse.handle,
                ehandle);
        /*} catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
            throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
        }*/

        //try {
        tpmNew.FlushContext(cpResponse.handle);
        /*} catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
            throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
        }*/
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
        int index = findKeyHandle("0x81018000");
        if (index != 0) {

            TPM_HANDLE handle = TPM_HANDLE.from(TPM_RH.OWNER);
            handle.AuthValue = ownerAuth;
            //try {
            tpmNew.EvictControl(handle, TPM_HANDLE.from(0x81018000),
                    TPM_HANDLE.from(0x81018000));
            /*} catch (tss.TpmException e) {
                LOG.debug("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
                throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
            }*/
        }
    }

    @Override
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);

        byte[] nonceCaller = TpmUtils.createRandomBytes(20);
        // Start a policy session to be used with ActivateCredential()
        StartAuthSessionResponse sasResponse = tpmNew.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                nonceCaller, new byte[0], TPM_SE.POLICY,
                TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

        TPM_HANDLE endorseHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
        endorseHandle.AuthValue = ownerAuth;
        // Apply the policy necessary to authorize an EK on Windows
        PolicySecretResponse psResp = tpmNew.PolicySecret(endorseHandle, sasResponse.handle,
                new byte[0], new byte[0], new byte[0], 0);

        TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.sign,
                        TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.NULL, 0, TPM_ALG_ID.NULL),
                        new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),2048,65537),
                new TPM2B_PUBLIC_KEY_RSA());

        TPM_HANDLE ehandle = TPM_HANDLE.from(ekHandle);
        ehandle.AuthValue = ownerAuth;
        CreateResponse cResponse = tpmNew._withSession(sasResponse.handle).Create(ehandle,
                new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
        System.out.println("create response : " + cResponse.toString());
        tpmNew.FlushContext(sasResponse.handle);

        // Start a policy session to be used with ActivateCredential()
        sasResponse = tpmNew.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                nonceCaller, new byte[0], TPM_SE.POLICY,
                TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

        // Apply the policy necessary to authorize an EK on Windows
        psResp = tpmNew.PolicySecret(endorseHandle, sasResponse.handle,
                new byte[0], new byte[0], new byte[0], 0);

        TPM_HANDLE loadHandle = tpmNew._withSession(sasResponse.handle).Load(ehandle, cResponse.outPrivate, cResponse.outPublic);
        tpmNew.FlushContext(sasResponse.handle);

        TPM_HANDLE ohandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ohandle.AuthValue = ownerAuth;
        byte[] persistent = new byte[] { (byte) 0x81, 0x01, (byte) 0x80, 0x00 };
        TPM_HANDLE ahandle = TPM_HANDLE.fromTpm(persistent);
        ahandle.AuthValue = keyAuth;
        //try {
        tpmNew.EvictControl(ohandle, loadHandle,
                ahandle);
        /*} catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
            throw new Tpm.TpmException("TpmLinuxV20.takeOwnership failed to make storage primary key persistent");
        }*/
        tpmNew.FlushContext(loadHandle);

        ReadPublicResponse akPub = tpmNew.ReadPublic(ahandle);
        System.out.println("akPub : " + akPub.toString());

        // TPM 2.0 identityRequest and aikpub are used as the same
        IdentityRequest newId = new IdentityRequest(this.getTpmVersion(),
                ((TPM2B_PUBLIC_KEY_RSA)akPub.outPublic.unique).buffer,
                ((TPM2B_PUBLIC_KEY_RSA)akPub.outPublic.unique).buffer, persistent, akPub.name);
        return newId;
    }

    @Override
    public byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest)
            throws IOException, Tpm.TpmException {
        int akHandle = findAikHandle();
        int ekHandle = findEkHandle();
        LOG.debug(" AIK Handle : {}", akHandle);

        byte[] nonceCaller = TpmUtils.createRandomBytes(20);
        // Start a policy session to be used with ActivateCredential()
        StartAuthSessionResponse sasResponse = tpmNew.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                nonceCaller, new byte[0], TPM_SE.POLICY,
                TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

        TPM_HANDLE endorseHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
        endorseHandle.AuthValue = ownerAuth;
        // Apply the policy necessary to authorize an EK on Windows
        PolicySecretResponse psResp = tpmNew.PolicySecret(endorseHandle, sasResponse.handle,
                new byte[0], new byte[0], new byte[0], 0);

        byte[] credential = proofRequest.getCredential();
        byte[] secret = proofRequest.getSecret();
        byte[] integrityHMAC = Arrays.copyOfRange(credential, 4, 4 + 32);
        byte[] encIdentity = Arrays.copyOfRange(credential,36, 36 + 18);
        secret = Arrays.copyOfRange(secret, 2, 2 + 256);
        TPMS_ID_OBJECT credentialBlob = new TPMS_ID_OBJECT(integrityHMAC, encIdentity);

        TPM_HANDLE ehandle = TPM_HANDLE.from(ekHandle);
        ehandle.AuthValue = ownerAuth;
        TPM_HANDLE ahandle = TPM_HANDLE.from(akHandle);
        ahandle.AuthValue = ownerAuth;
        byte[] recoveredSecret = tpmNew._withSessions(TPM_HANDLE.pwSession(keyAuth),
                sasResponse.handle).ActivateCredential(ahandle, ehandle, credentialBlob, secret);
        System.out.println("recovered secret : " + TpmUtils.byteArrayToHexString(recoveredSecret));
        tpmNew.FlushContext(sasResponse.handle);

        try {
            return Utils.decryptSymCaAttestation(recoveredSecret, proofRequest.getSymBlob());
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

    private PCR_ReadResponse getPcrsRequired(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) throws IOException {
        PCR_ReadResponse pcrsRequired = null;
        for(TPMS_PCR_SELECTION pcrSelection: getTpmsPcrSelections(pcrBanks, pcrs)) {
            PCR_ReadResponse pcrsNew = tpmNew.PCR_Read(new TPMS_PCR_SELECTION[]{pcrSelection});
            if( pcrsRequired == null) {
                pcrsRequired = pcrsNew;
            } else {
                pcrsRequired.pcrSelectionOut = concatPcrSelect(pcrsRequired.pcrSelectionOut, pcrsNew.pcrSelectionOut);
                pcrsRequired.pcrValues = concatDigest(pcrsRequired.pcrValues, pcrsNew.pcrValues);
            }
        }
        return pcrsRequired;
    }

    private TPMS_PCR_SELECTION[] concatPcrSelect(TPMS_PCR_SELECTION[] blob1, TPMS_PCR_SELECTION[] blob2) {
        TPMS_PCR_SELECTION[] toReturn = new TPMS_PCR_SELECTION[blob1.length + blob2.length];
        int i = 0;
        for(TPMS_PCR_SELECTION digest: blob1) {
            toReturn[i] = digest;
            i++;
        }
        for(TPMS_PCR_SELECTION digest: blob2) {
            toReturn[i] = digest;
            i++;
        }
        return toReturn;
    }

    private TPM2B_DIGEST[] concatDigest(TPM2B_DIGEST[] blob1, TPM2B_DIGEST[] blob2) {
        TPM2B_DIGEST[] toReturn = new TPM2B_DIGEST[blob1.length + blob2.length];
        int i = 0;
        for(TPM2B_DIGEST digest: blob1) {
            toReturn[i] = digest;
            i++;
        }
        for(TPM2B_DIGEST digest: blob2) {
            toReturn[i] = digest;
            i++;
        }
        return toReturn;
    }

    @Override
    public TpmQuote getQuote(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs, byte[] aikBlob, byte[] aikAuth, byte[] nonce)
            throws IOException, Tpm.TpmException {
        byte[] pcrsResult = getPcrs(pcrBanks, pcrs);
        System.out.println("PcrList: " + TpmUtils.byteArrayToHexString(pcrsResult));

        TPMS_PCR_SELECTION[] selectedPcrsToQuote = getTpmsPcrToQuoteSelections(pcrBanks, pcrs);
        TPM_HANDLE handle = TPM_HANDLE.from(ByteBuffer.wrap(aikBlob).order(ByteOrder.BIG_ENDIAN).getInt());
        handle.AuthValue = aikAuth;
        QuoteResponse quote = tpmNew.Quote(handle, nonce, new TPMS_NULL_SIG_SCHEME(), selectedPcrsToQuote);
        System.out.println("Quote: " + quote.toString());

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
        return changeAuth(ownerAuth, ownerAuth);
    }

}
