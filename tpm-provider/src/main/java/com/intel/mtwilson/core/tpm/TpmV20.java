/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.util.PcrBanksMapper;
import com.intel.mtwilson.core.tpm.util.Utils;
import gov.niarl.his.privacyca.TpmUtils;
import org.apache.commons.lang.ArrayUtils;
import tss.TpmDeviceBase;
import tss.tpm.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.PublicKey;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.intel.mtwilson.core.tpm.util.NvAttributeMapper.getTpmaNvFromAttributes;

/**
 *
 * @author rawatar, ddhawal
 */
abstract public class TpmV20 extends Tpm {
    private final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(TpmV20.class);
    private tss.Tpm tpm;

    TpmV20(TpmDeviceBase base) {
        tpm = new tss.Tpm();
        tpm._setDevice(base);
    }

    //TODO: Remove after implentation of getEK in windows
    TpmV20(String tpmToolsPath, TpmDeviceBase base) {
        super(tpmToolsPath);
        tpm = new tss.Tpm();
        tpm._setDevice(base);
    }

    private boolean changeAuth(byte[] oldAuth, byte[] newAuth) {
        Set<TPM_HANDLE> handles = new HashSet<>(Arrays.asList(TPM_HANDLE.from(TPM_RH.OWNER),
                TPM_HANDLE.from(TPM_RH.ENDORSEMENT), TPM_HANDLE.from(TPM_RH.LOCKOUT)));

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
        if (!changeAuth(null, ownerAuth)) {
            byte[] newOwnerPass = TpmUtils.createRandomBytes(20);
            if (!changeAuth(ownerAuth, newOwnerPass)) {
                // supplied newOwnerAuth is invalid
                log.debug("Cannot take ownership; TPM claimed with a different password");
                throw new Tpm.TpmException("Cannot take ownership; TPM claimed with a different password");
            } else {
                // supplied newOwnerAuth is valid, so change TPM owner pass back from the temporary and do it again
                if (!changeAuth(newOwnerPass, ownerAuth)) {
                    log.debug("CRITICAL ERROR: Could not change TPM password back from temporary. TPM must be reset from bios");
                    throw new Tpm.TpmException("CRITICAL ERROR: "
                            + "Could not change TPM password back from temporary. TPM must be reset from bios");
                }
            }
        }
    }

    @Override
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, Tpm.TpmException {
        // basically do what tpm2-isowner.sh did, take ownership and see if we can change it and revert it from a temporary
        changeAuth(newOwnerAuth);

        TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.decrypt,
                        TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                new byte[0],
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                        new TPMS_NULL_ASYM_SCHEME(),2048,0),
                new TPM2B_PUBLIC_KEY_RSA());

        CreatePrimaryResponse cpResponse;
        TPM_HANDLE oHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        oHandle.AuthValue = newOwnerAuth;
        try {
            cpResponse = tpm.CreatePrimary(oHandle,
                    new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
        } catch (tss.TpmException e) {
            log.debug("Failed to create storage primary key");
            throw new Tpm.TpmException("Failed to create storage primary key");
        }

        byte[] persistent = new byte[] { (byte) 0x81, 0x00, 0x00, 0x00 };
        try {
            tpm.EvictControl(oHandle, cpResponse.handle,
                    TPM_HANDLE.fromTpm(persistent));
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("NV_DEFINED")) {
                log.debug("Failed to make storage primary key persistent");
                throw new Tpm.TpmException("Failed to make storage primary key persistent");
            }
        }
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

    private int findKeyHandle(String mask) throws Tpm.TpmException {
        GetCapabilityResponse gcResponse;
        try {
            gcResponse = tpm.GetCapability(TPM_CAP.HANDLES,
                    TPM_HT.PERSISTENT.toInt() << 24, 16);
        } catch(tss.TpmException e) {
            log.debug("Failed to list key handles");
            throw new Tpm.TpmException("Failed to list key handles");
        }
        TPML_HANDLE handles = (TPML_HANDLE) gcResponse.capabilityData;

        Pattern p = Pattern.compile(mask);
        Matcher m;
        for (int i = 0; i < handles.handle.length; i++) {
            m = p.matcher(handles.handle[i].toString());
            if (m.find()) {
                return Long.decode(m.group()).intValue();
            }
        }
        return 0;
    }

    private int findAikHandle() throws Tpm.TpmException {
        for (int i = 0x81018; i < 0x81020; i++) {
            int index = findKeyHandle(String.format("0x%05x...", i));
            if (index != 0) {
                return index;
            }
        }
        throw new Tpm.TpmException("Could not find AIK Handle");
    }

    private int findEkHandle() throws Tpm.TpmException {
        int index = findKeyHandle("0x810100..");
        if (index != 0) {
            return index;
        } else {
            throw new Tpm.TpmException("Could not find EK Handle");
        }
    }

    private int getNextUsableHandle() throws Tpm.TpmException {
        GetCapabilityResponse gcResponse;
        try {
            gcResponse = tpm.GetCapability(TPM_CAP.HANDLES,
                    TPM_HT.PERSISTENT.toInt() << 24, 16);
        } catch(tss.TpmException e) {
            log.debug("Failed to list key handles");
            throw new Tpm.TpmException("Failed to list key handles");
        }
        TPML_HANDLE handles = (TPML_HANDLE) gcResponse.capabilityData;

        int index = 0x81010000;
        int count;
        for (int j = 0; j <= 255; j++) {
            count = 0;
            for (int i = 0; i < handles.handle.length; i++) {
                if (!handles.handle[i].toString().contains(String.format("0x%08x", index + j))) {
                    count++;
                }
            }
            if (count == handles.handle.length) {
                return index + j;
            }
        }
        throw new Tpm.TpmException("No usable persistent handles are available");
    }

    private int createEk(byte[] ownerAuth, byte[] endorsePass) throws Tpm.TpmException {
        int ekHandle = getNextUsableHandle();

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

        try {
            TPM_HANDLE eHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
            eHandle.AuthValue = endorsePass;
            CreatePrimaryResponse cpResponse = tpm.CreatePrimary(eHandle,
                    new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);

            TPM_HANDLE oHandle = TPM_HANDLE.from(TPM_RH.OWNER);
            oHandle.AuthValue = ownerAuth;
            tpm.EvictControl(oHandle, cpResponse.handle,
                    TPM_HANDLE.from(ekHandle));

            tpm.FlushContext(cpResponse.handle);
        } catch (tss.TpmException e) {
            log.debug("Failed to create EK");
            throw new Tpm.TpmException("Failed to create EK");
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

    private void clearAkHandle(byte[] ownerAuth) throws Tpm.TpmException {
        int index = findKeyHandle("0x81018000");
        if (index != 0) {

            TPM_HANDLE oHandle = TPM_HANDLE.from(TPM_RH.OWNER);
            oHandle.AuthValue = ownerAuth;
            try {
                tpm.EvictControl(oHandle, TPM_HANDLE.from(index),
                        TPM_HANDLE.from(index));
            } catch (tss.TpmException e) {
                log.debug("Failed to clear AIK handle");
                throw new Tpm.TpmException("Failed to clear AIK handle");
            }
        }
    }

    @Override
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);

        ReadPublicResponse ekPub;
        try {
            ekPub = tpm.ReadPublic(TPM_HANDLE.from(ekHandle));
        } catch (tss.TpmException e) {
            log.debug("Failed to read public key");
            throw new Tpm.TpmException("Failed to read public key");
        }

        return ((TPM2B_PUBLIC_KEY_RSA)ekPub.outPublic.unique).buffer;
    }

    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, Tpm.TpmException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);
        log.info("CollateIdentityRequest using EkHandle: {}", String.format("0x%08x", ekHandle));
        // existing akHandle so we can use it
        clearAkHandle(ownerAuth);

        ReadPublicResponse akPub;
        byte[] persistent = new byte[] { (byte) 0x81, 0x01, (byte) 0x80, 0x00 };
        try {
            byte[] nonceCaller = TpmUtils.createRandomBytes(20);
            StartAuthSessionResponse sasResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            TPM_HANDLE eHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
            eHandle.AuthValue = ownerAuth;
            tpm.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            TPMS_SENSITIVE_CREATE inSensitive = new TPMS_SENSITIVE_CREATE(keyAuth, new byte[0]);

            TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                    new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.sign,
                            TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                    new byte[0],
                    new TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT.nullObject(),
                            new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),2048,65537),
                    new TPM2B_PUBLIC_KEY_RSA());

            CreateResponse cResponse = tpm._withSession(sasResponse.handle).Create(TPM_HANDLE.from(ekHandle),
                    inSensitive, inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
            tpm.FlushContext(sasResponse.handle);

            sasResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            tpm.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            TPM_HANDLE loadHandle = tpm._withSession(sasResponse.handle).Load(TPM_HANDLE.from(ekHandle),
                    cResponse.outPrivate, cResponse.outPublic);
            tpm.FlushContext(sasResponse.handle);

            TPM_HANDLE oHandle = TPM_HANDLE.from(TPM_RH.OWNER);
            oHandle.AuthValue = ownerAuth;
            loadHandle.AuthValue = inSensitive.userAuth;
            tpm.EvictControl(oHandle, loadHandle,
                    TPM_HANDLE.fromTpm(persistent));
            tpm.FlushContext(loadHandle);

            akPub = tpm.ReadPublic(TPM_HANDLE.fromTpm(persistent));
        } catch (tss.TpmException e) {
            log.debug("Failed to create AIK");
            throw new Tpm.TpmException("Failed to create AIK");
        }

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
        log.debug("AIK Handle : {}", akHandle);

        byte[] recoveredSecret;
        try {
            byte[] nonceCaller = TpmUtils.createRandomBytes(20);
            StartAuthSessionResponse sasResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            TPM_HANDLE eHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
            eHandle.AuthValue = ownerAuth;
            tpm.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            byte[] credential = proofRequest.getCredential();
            byte[] secret = proofRequest.getSecret();
            byte[] integrityHMAC = Arrays.copyOfRange(credential, 4, 4 + 32);
            byte[] encIdentity = Arrays.copyOfRange(credential,36, 36 + 18);
            secret = Arrays.copyOfRange(secret, 2, 2 + 256);
            TPMS_ID_OBJECT credentialBlob = new TPMS_ID_OBJECT(integrityHMAC, encIdentity);

            TPM_HANDLE aHandle = TPM_HANDLE.from(akHandle);
            aHandle.AuthValue = keyAuth;
            recoveredSecret = tpm._withSessions(TPM_HANDLE.pwSession(new byte[0]),
                    sasResponse.handle).ActivateCredential(aHandle, TPM_HANDLE.from(ekHandle), credentialBlob, secret);
            tpm.FlushContext(sasResponse.handle);
        } catch (tss.TpmException e) {
            throw new Tpm.TpmException("Failed to activate credential");
        }

        try {
            return Utils.decryptSymCaAttestation(recoveredSecret, proofRequest.getSymBlob());
        } catch (BufferUnderflowException | Utils.SymCaDecryptionException ex) {
            log.debug("ActivateIdentity failed with exception", ex);
            throw new Tpm.TpmException("ActivateIdentity failed with exception", ex);
        }
    }

    @Override
    public void setAssetTag(byte[] ownerAuth, byte[] assetTagHash) throws IOException, Tpm.TpmException {
        int index = getAssetTagIndex();
        if (nvIndexExists(index)) {
            log.debug("Index {} already exists. Releasing index...", index);
            nvRelease(ownerAuth, index);
            log.debug("Creating new index...");
        } else {
            log.debug("Index does not exist, creating it...");
        }
        nvDefine(ownerAuth, ownerAuth, index, 32, Tpm.NVAttribute.AUTHWRITE, Tpm.NVAttribute.AUTHREAD);
        nvWrite(ownerAuth, index, assetTagHash);
        log.debug("Successfully provisioned asset tag");
    }

    @Override
    public byte[] readAssetTag(byte[] ownerAuth) throws Tpm.TpmException {
        int index = getAssetTagIndex();
        log.debug("Reading asset tag at index {}", index);
        if (nvIndexExists(index)) {
            log.debug("Index {} exists", index);
            return nvRead(ownerAuth, index, 32);
        } else {
            throw new Tpm.TpmException("Asset tag has not been provisioned on this TPM");
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
        GetCapabilityResponse caps = tpm.GetCapability(TPM_CAP.ALGS, 0, TPM_ALG_ID.values().size());
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
            log.debug("Failed to retrieve list of PCR banks");
            throw new Tpm.TpmException("Failed to retrieve list of PCR Banks");
        }
        return supportedPcrBanks;
    }

    @Override
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<Tpm.NVAttribute> attributes) throws Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        TPMA_NV nvAttributes = getTpmaNvFromAttributes(attributes);
        TPMS_NV_PUBLIC nvPub = new TPMS_NV_PUBLIC(nvHandle, TPM_ALG_ID.SHA256, nvAttributes, new byte[0], size);
        try {
            tpm.NV_DefineSpace(ownerHandle, indexPassword, nvPub);
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("NV_DEFINED")) {
                log.debug("nvDefine returned error {}", e.getMessage());
                throw new Tpm.TpmException("nvDefine returned error", e);
            }
        }
    }

    @Override
    public void nvRelease(byte[] ownerAuth, int index) throws Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        TPM_HANDLE nvIndex = new TPM_HANDLE(index);
        try {
            tpm.NV_UndefineSpace(ownerHandle, nvIndex);
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("HANDLE")) {
                log.debug("nvRelease returned error {}", e.getMessage());
                throw new Tpm.TpmException("nvRelease returned error", e);
            }
        }
    }

    @Override
    public byte[] nvRead(byte[] authPassword, int index, int size) throws Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(index);
        ownerHandle.AuthValue = authPassword;
        TPM_HANDLE nvIndex = new TPM_HANDLE(index);
        byte[] data;
        try {
            data = tpm.NV_Read(ownerHandle, nvIndex,  size,  0);
        } catch (tss.TpmException e) {
            log.debug("nvRead returned error {}", e.getMessage());
            throw new Tpm.TpmException("nvRead returned error ", e);
        }
        return data;
    }

    @Override
    public void nvWrite(byte[] authPassword, int index, byte[] data) throws Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(index);
        ownerHandle.AuthValue = authPassword;
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        try {
            tpm.NV_Write(ownerHandle, nvHandle, data,  0);
        } catch (tss.TpmException e) {
            log.debug("nvWrite returned error {}", e.getMessage());
            throw new Tpm.TpmException("nvWrite returned error ", e);
        }
    }

    @Override
    public boolean nvIndexExists(int index) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        NV_ReadPublicResponse nvPub;
        try {
            nvPub = tpm.NV_ReadPublic(nvHandle);
        } catch (tss.TpmException e) {
            if(e.getMessage().contains("HANDLE")) {
                return false;
            } else {
                log.debug("nvIndexExists returned error {}", e.getMessage());
                throw new Tpm.TpmException("nvIndexExists returned error", e);
            }
        }
        return index == nvPub.nvPublic.nvIndex.handle;
    }

    @Override
    public TpmQuote getQuote(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs, byte[] aikBlob, byte[] aikAuth, byte[] nonce)
            throws IOException, Tpm.TpmException {
        byte[] pcrsResult = getPcrs(pcrBanks, pcrs);

        TPMS_PCR_SELECTION[] selectedPcrsToQuote = getTpmsPcrToQuoteSelections(pcrBanks, pcrs);
        TPM_HANDLE aHandle = TPM_HANDLE.from(ByteBuffer.wrap(aikBlob).order(ByteOrder.BIG_ENDIAN).getInt());
        aHandle.AuthValue = aikAuth;
        QuoteResponse quote;
        try {
            quote = tpm.Quote(aHandle, nonce, new TPMS_NULL_SIG_SCHEME(), selectedPcrsToQuote);
        } catch (tss.TpmException e) {
            throw new Tpm.TpmException("getQuote failed to generate quote");
        }

        byte[] combined = ArrayUtils.addAll(quote.toTpm(), pcrsResult);
        return new TpmQuote(System.currentTimeMillis(), pcrBanks, combined);
    }

    // As 'PCR_Read' does not result more than 8 PCR values, we need to read them in chunks
    private byte[] getPcrs(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) throws IOException {
        ByteArrayOutputStream pcrStream = new ByteArrayOutputStream();
        for(TPMS_PCR_SELECTION pcrSelection: getTpmsPcrSelections(pcrBanks, pcrs)) {
            PCR_ReadResponse pcrsNew = tpm.PCR_Read(new TPMS_PCR_SELECTION[]{pcrSelection});
            for(TPM2B_DIGEST digest : pcrsNew.pcrValues) {
                pcrStream.write(digest.buffer);
            }
        }
        return pcrStream.toByteArray();
    }

    private TPMS_PCR_SELECTION[] getTpmsPcrToQuoteSelections(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) {
        int[] pcrLists = pcrs.stream().map(Tpm.Pcr::toInt).mapToInt(i->i).toArray();
        Arrays.sort(pcrLists);
        List<TPMS_PCR_SELECTION> selectedPcrs = new ArrayList<>();
        for(TPM_ALG_ID alg : PcrBanksMapper.getMappedPcrBanks(pcrBanks)) {
            selectedPcrs.add(new TPMS_PCR_SELECTION(alg, pcrLists));
        }
        return selectedPcrs.toArray(new TPMS_PCR_SELECTION[selectedPcrs.size()]);
    }

    private TPMS_PCR_SELECTION[] getTpmsPcrSelections(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) {
        int[] pcrLists = pcrs.stream().map(Tpm.Pcr::toInt).mapToInt(i->i).toArray();
        Arrays.sort(pcrLists);
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

    private int nvIndexSize(int index) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        NV_ReadPublicResponse nvPub;
        try {
            nvPub = tpm.NV_ReadPublic(nvHandle);
        } catch (Exception e) {
            log.debug("nvIndexSize could not find size of index {}", String.format("0x%08x", index));
            throw new Tpm.TpmException("nvIndexSize could not find size of index " + String.format("0x%08x", index));
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
