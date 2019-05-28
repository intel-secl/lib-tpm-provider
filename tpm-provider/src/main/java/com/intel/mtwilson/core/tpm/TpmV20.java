/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import com.intel.mtwilson.core.tpm.model.PersistentIndex;
import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.util.PcrBanksMapper;
import com.intel.mtwilson.core.tpm.util.Utils;
import gov.niarl.his.privacyca.TpmUtils;
import org.apache.commons.lang.ArrayUtils;
import tss.TpmDeviceBase;
import tss.tpm.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
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
    protected tss.Tpm tpm;

    TpmV20(TpmDeviceBase base) {
        tpm = new tss.Tpm();
        tpm._setDevice(base);
    }

    private int findKeyHandle(String mask) throws Tpm.TpmException {
        GetCapabilityResponse gcResponse;
        try {
            gcResponse = tpm.GetCapability(TPM_CAP.HANDLES,
                    TPM_HT.PERSISTENT.toInt() << 24, 16);
        } catch(tss.TpmException e) {
            log.error("Failed to list key handles");
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
            log.error("Failed to list key handles");
            throw new Tpm.TpmException("Failed to list key handles");
        }
        TPML_HANDLE handles = (TPML_HANDLE) gcResponse.capabilityData;

        int index = PersistentIndex.EK.getValue();
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

        // This policy is a "standard" policy that is used with vendor-provided
        // EKs
        byte[] standardEKPolicy = new byte[] {
                (byte)0x83, 0x71, (byte)0x97, 0x67, 0x44, (byte)0x84, (byte)0xB3, (byte)0xF8, 0x1A, (byte)0x90, (byte)0xCC,
                (byte)0x8D, 0x46, (byte)0xA5, (byte)0xD7, 0x24, (byte)0xFD, 0x52, (byte)0xD7, 0x6E, 0x06, 0x52,
                0x0B, 0x64, (byte)0xF2, (byte)0xA1, (byte)0xDA, 0x1B, 0x33, 0x14, 0x69, (byte)0xAA
        };

        TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.adminWithPolicy, TPMA_OBJECT.decrypt,
                        TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                standardEKPolicy,
                new TPMS_RSA_PARMS(new TPMT_SYM_DEF_OBJECT(TPM_ALG_ID.AES, 128, TPM_ALG_ID.CFB),
                        new TPMS_NULL_ASYM_SCHEME(),2048,0),
                new TPM2B_PUBLIC_KEY_RSA());

        try {
            TPM_HANDLE eHandle = getEndorsementHandle(endorsePass);
            CreatePrimaryResponse cpResponse = tpm.CreatePrimary(eHandle,
                    new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);

            TPM_HANDLE oHandle = getOwnerHandle(ownerAuth);
            tpm.EvictControl(oHandle, cpResponse.handle,
                    TPM_HANDLE.from(ekHandle));

            tpm.FlushContext(cpResponse.handle);
        } catch (tss.TpmException e) {
            log.error("Failed to create EK");
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

    private void clearAikHandle(byte[] ownerAuth) throws Tpm.TpmException {
        int index = findKeyHandle(String.valueOf(PersistentIndex.AIK.getValue()));
        if (index != 0) {
            TPM_HANDLE oHandle = getOwnerHandle(ownerAuth);
            try {
                tpm.EvictControl(oHandle, TPM_HANDLE.from(index),
                        TPM_HANDLE.from(index));
            } catch (tss.TpmException e) {
                log.error("Failed to clear AIK handle");
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
            log.error("Failed to retrieve EK public part");
            throw new Tpm.TpmException("Failed to retrieve EK public part");
        }

        return ((TPM2B_PUBLIC_KEY_RSA)ekPub.outPublic.unique).buffer;
    }

    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, Tpm.TpmException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);
        log.debug("CollateIdentityRequest using EkHandle: {}", String.format("0x%08x", ekHandle));
        // clear existing aikHandle so we can use it
        clearAikHandle(ownerAuth);

        ReadPublicResponse aikPub;
        try {
            // Make a session to authorize the key creation
            byte[] nonceCaller = TpmUtils.createRandomBytes(20);
            StartAuthSessionResponse sasResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            // check that the policy is what it should be!
            TPM_HANDLE eHandle = getEndorsementHandle(ownerAuth);
            tpm.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            // Tell the TPM to make a key with a non-null auth value
            TPMS_SENSITIVE_CREATE inSensitive = new TPMS_SENSITIVE_CREATE(keyAuth, new byte[0]);

            // Create an RSA restricted signing key in the owner hierarchy
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

            // load the new key
            TPM_HANDLE loadHandle = tpm._withSession(sasResponse.handle).Load(TPM_HANDLE.from(ekHandle),
                    cResponse.outPrivate, cResponse.outPublic);
            tpm.FlushContext(sasResponse.handle);

            TPM_HANDLE oHandle = getOwnerHandle(ownerAuth);
            // Since the key has non-null auth, we need to set it explicitly in the
            // handle
            loadHandle.AuthValue = inSensitive.userAuth;
            tpm.EvictControl(oHandle, loadHandle,
                    TPM_HANDLE.from(PersistentIndex.AIK.getValue()));
            tpm.FlushContext(loadHandle);

            aikPub = tpm.ReadPublic(TPM_HANDLE.from(PersistentIndex.AIK.getValue()));
        } catch (tss.TpmException e) {
            log.error("Failed to create AIK");
            throw new Tpm.TpmException("Failed to create AIK");
        }

        BigInteger aikBigInt = BigInteger.valueOf(PersistentIndex.AIK.getValue());
        // TPM 2.0 identityRequest and aikPub are used as the same
        IdentityRequest newId = new IdentityRequest(this.getTpmVersion(),
                ((TPM2B_PUBLIC_KEY_RSA)aikPub.outPublic.unique).buffer,
                ((TPM2B_PUBLIC_KEY_RSA)aikPub.outPublic.unique).buffer, aikBigInt.toByteArray(), aikPub.name);
        return newId;
    }

    @Override
    public byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest)
            throws IOException, Tpm.TpmException {
        int aikHandle = findAikHandle();
        int ekHandle = findEkHandle();

        /*
         Credential consists of:
                2 bytes Credential size
                2 bytes Integrity size
                32 bytes Integrity data
                18 bytes Encrypted data
         */
        byte[] credential = proofRequest.getCredential();
        // copying Integrity data (36 - 4 = 32 bytes)
        byte[] integrityHMAC = Arrays.copyOfRange(credential, 4, 36);
        // copying Encrypted data (54 - 36 = 18 bytes)
        byte[] encIdentity = Arrays.copyOfRange(credential,36, 54);
        TPMS_ID_OBJECT credentialBlob = new TPMS_ID_OBJECT(integrityHMAC, encIdentity);

        /*
         Secret consists of:
                2 bytes Secret size
                256 bytes Secret data
         */
        byte[] secret = proofRequest.getSecret();
        secret = Arrays.copyOfRange(secret, 2, 258);

        byte[] recoveredSecret;
        try {
            byte[] nonceCaller = TpmUtils.createRandomBytes(20);
            StartAuthSessionResponse sasResponse = tpm.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            TPM_HANDLE eHandle = getEndorsementHandle(ownerAuth);
            tpm.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            TPM_HANDLE aHandle = getIndexHandle(aikHandle, keyAuth);
            recoveredSecret = tpm._withSessions(TPM_HANDLE.pwSession(new byte[0]),
                    sasResponse.handle).ActivateCredential(aHandle, TPM_HANDLE.from(ekHandle), credentialBlob, secret);
            tpm.FlushContext(sasResponse.handle);
        } catch (tss.TpmException e) {
            log.error("Failed to activate credential");
            throw new Tpm.TpmException("Failed to activate credential");
        }

        try {
            return Utils.decryptSymCaAttestation(recoveredSecret, proofRequest.getSymBlob());
        } catch (BufferUnderflowException | Utils.SymCaDecryptionException ex) {
            log.error("ActivateIdentity failed with exception", ex);
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
        nvDefine(ownerAuth, ownerAuth, index, 48, Tpm.NVAttribute.AUTHWRITE, Tpm.NVAttribute.AUTHREAD);
        nvWrite(ownerAuth, index, assetTagHash);
        log.debug("Successfully provisioned asset tag");
    }

    @Override
    public byte[] readAssetTag(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        int index = getAssetTagIndex();
        log.debug("Reading asset tag at index {}", index);
        if (nvIndexExists(index)) {
            log.debug("Index {} exists", index);
            return nvRead(ownerAuth, index, 48);
        } else {
            throw new Tpm.TpmException("Asset tag has not been provisioned on this TPM");
        }
    }

    @Override
    public int getAssetTagIndex() {
        return 0x1c10110;
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
            log.error("Failed to retrieve list of PCR banks");
            throw new Tpm.TpmException("Failed to retrieve list of PCR Banks");
        }
        return supportedPcrBanks;
    }

    @Override
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<Tpm.NVAttribute> attributes) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        TPMA_NV nvAttributes = getTpmaNvFromAttributes(attributes);
        TPMS_NV_PUBLIC nvPub = new TPMS_NV_PUBLIC(nvHandle, TPM_ALG_ID.SHA256, nvAttributes, new byte[0], size);
        try {
            // Make a new simple NV slot
            tpm.NV_DefineSpace(getOwnerHandle(ownerAuth), indexPassword, nvPub);
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("NV_DEFINED")) {
                log.error("nvDefine returned error {}", e.getMessage());
                throw new Tpm.TpmException("nvDefine returned error", e);
            }
        }
    }

    @Override
    public void nvRelease(byte[] ownerAuth, int index) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        try {
            // Delete the NV slot if it exists
            tpm.NV_UndefineSpace(getOwnerHandle(ownerAuth), nvHandle);
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("HANDLE")) {
                log.error("nvRelease returned error {}", e.getMessage());
                throw new Tpm.TpmException("nvRelease returned error", e);
            }
        }
    }

    @Override
    public byte[] nvRead(byte[] authPassword, int index, int size, int offset) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        byte[] data;
        try {
            // Read data from NV slot
            data = tpm.NV_Read(getIndexHandle(index, authPassword), nvHandle,  size,  offset);
        } catch (tss.TpmException e) {
            log.error("nvRead returned error {}", e.getMessage());
            throw new Tpm.TpmException("nvRead returned error ", e);
        }
        return data;
    }

    @Override
    public void nvWrite(byte[] authPassword, int index, byte[] data) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        try {
            // Write data to NV slot
            tpm.NV_Write(getIndexHandle(index, authPassword), nvHandle, data,  0);
        } catch (tss.TpmException e) {
            log.error("nvWrite returned error {}", e.getMessage());
            throw new Tpm.TpmException("nvWrite returned error ", e);
        }
    }

    @Override
    public boolean nvIndexExists(int index) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        NV_ReadPublicResponse nvPub;
        try {
            // Read the public area from NV slot
            nvPub = tpm.NV_ReadPublic(nvHandle);
        } catch (tss.TpmException e) {
            if(e.getMessage().contains("HANDLE")) {
                return false;
            } else {
                log.error("nvIndexExists returned error {}", e.getMessage());
                throw new Tpm.TpmException("nvIndexExists returned error", e);
            }
        }
        return index == nvPub.nvPublic.nvIndex.handle;
    }

    @Override
    public TpmQuote getQuote(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs, byte[] aikHandle, byte[] aikAuth, byte[] nonce)
            throws IOException, Tpm.TpmException {
        byte[] pcrsResult = getPcrs(pcrBanks, pcrs);

        // Quote selected PCR
        TPMS_PCR_SELECTION[] selectedPcrsToQuote = getTpmsPcrToQuoteSelections(pcrBanks, pcrs);
        TPM_HANDLE aHandle = TPM_HANDLE.fromTpm(aikHandle);
        aHandle.AuthValue = aikAuth;
        QuoteResponse quote;
        try {
            quote = tpm.Quote(aHandle, nonce, new TPMS_NULL_SIG_SCHEME(), selectedPcrsToQuote);
        } catch (tss.TpmException e) {
            log.error("Failed to generate quote");
            throw new Tpm.TpmException("Failed to generate quote", e);
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

    // Form array of required values of PCR for each Digest algorithm in chunks of 8
    private TPMS_PCR_SELECTION[] getTpmsPcrSelections(Set<Tpm.PcrBank> pcrBanks, Set<Tpm.Pcr> pcrs) {
        int[] pcrLists = pcrs.stream().map(Tpm.Pcr::toInt).mapToInt(i->i).toArray();
        Arrays.sort(pcrLists);
        List<TPMS_PCR_SELECTION> selectedPcrs = new ArrayList<>();
        for(TPM_ALG_ID alg : PcrBanksMapper.getMappedPcrBanks(pcrBanks)) {
            if(pcrLists.length < 8) {
                selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 0, pcrLists.length)));
            } else {
                selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 0, 8)));
                if (pcrLists.length < 16) {
                    selectedPcrs.add(new TPMS_PCR_SELECTION(alg, Arrays.copyOfRange(pcrLists, 8, pcrLists.length)));
                } else {
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

    protected int nvIndexSize(int index) throws Tpm.TpmException {
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        NV_ReadPublicResponse nvPub;
        try {
            nvPub = tpm.NV_ReadPublic(nvHandle);
        } catch (Exception e) {
            log.error("nvIndexSize could not find size of index {}", String.format("0x%08x", index));
            throw new Tpm.TpmException("nvIndexSize could not find size of index " + String.format("0x%08x", index));
        }
        return nvPub.nvPublic.dataSize;
    }

    protected TPM_HANDLE getOwnerHandle(byte[] ownerAuth) {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        return ownerHandle;
    }

    private TPM_HANDLE getEndorsementHandle(byte[] endorsementAuth) {
        TPM_HANDLE endorsementHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
        endorsementHandle.AuthValue = endorsementAuth;
        return endorsementHandle;
    }

    private TPM_HANDLE getIndexHandle(int index, byte[] indexAuth) {
        TPM_HANDLE indexHandle = TPM_HANDLE.from(index);
        indexHandle.AuthValue = indexAuth;
        return indexHandle;
    }
}
