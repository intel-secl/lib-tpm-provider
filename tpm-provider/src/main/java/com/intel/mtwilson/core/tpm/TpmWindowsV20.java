/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.util.PcrBanksMapper;
import com.intel.mtwilson.core.tpm.util.Utils;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import gov.niarl.his.privacyca.TpmUtils;
import org.apache.commons.lang.ArrayUtils;
import tss.TpmDeviceTbs;
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
 * @author dczech
 */
class TpmWindowsV20 extends TpmWindows {

    private final static org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TpmWindowsV20.class);
    private tss.Tpm tpmNew;

    TpmWindowsV20(String tpmToolsPath) {
        super(tpmToolsPath);
        tpmNew = new tss.Tpm();
        tpmNew._setDevice(new TpmDeviceTbs());
    }

    private int findKeyHandle(String mask) throws Tpm.TpmException {
        GetCapabilityResponse gcResponse;
        try {
            gcResponse = tpmNew.GetCapability(TPM_CAP.HANDLES,
                    TPM_HT.PERSISTENT.toInt() << 24, 16);
        } catch(tss.TpmException e) {
            LOG.debug("TpmLinuxV20.findKeyHandle failed to list key handles");
            throw new Tpm.TpmException("TpmLinuxV20.findKeyHandle failed to list key handles");
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
        throw new Tpm.TpmException("TpmLinuxV20.findAk could not find Ak");
    }

    private int findEkHandle() throws Tpm.TpmException {
        int index = findKeyHandle("0x810100..");
        if (index != 0) {
            return index;
        } else {
            throw new Tpm.TpmException("TpmLinuxV20.findEk could not find Ek");
        }
    }

    private int getNextUsableHandle() throws Tpm.TpmException {
        GetCapabilityResponse gcResponse;
        try {
            gcResponse = tpmNew.GetCapability(TPM_CAP.HANDLES,
                    TPM_HT.PERSISTENT.toInt() << 24, 16);
        } catch(tss.TpmException e) {
            LOG.debug("TpmLinuxV20.findKeyHandle failed to list key handles");
            throw new Tpm.TpmException("TpmLinuxV20.findKeyHandle failed to list key handles");
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
        throw new Tpm.TpmException("TpmLinuxV20.getNextUsableHandle no usable persistent handles are available");
    }

    private int createEk(byte[] ownerAuth, byte[] endorsePass) throws Tpm.TpmException, IOException {
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
            CreatePrimaryResponse cpResponse = tpmNew.CreatePrimary(eHandle,
                    new TPMS_SENSITIVE_CREATE(), inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);

            TPM_HANDLE oHandle = TPM_HANDLE.from(TPM_RH.OWNER);
            oHandle.AuthValue = ownerAuth;
            tpmNew.EvictControl(oHandle, cpResponse.handle,
                    TPM_HANDLE.from(ekHandle));

            tpmNew.FlushContext(cpResponse.handle);
        } catch (tss.TpmException e) {
            LOG.debug("TpmLinuxV20.createEk failed to create ek");
            throw new Tpm.TpmException("TpmLinuxV20.createEk failed to create ek");
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
                tpmNew.EvictControl(oHandle, TPM_HANDLE.from(index),
                        TPM_HANDLE.from(index));
            } catch (tss.TpmException e) {
                LOG.debug("TpmLinuxV20.clearAkHandle failed to clear ak handle");
                throw new Tpm.TpmException("TpmLinuxV20.clearAkHandle failed to clear ak handle");
            }
        }
    }

    @Override
    public IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, Tpm.TpmException {
        int ekHandle = findOrCreateEk(ownerAuth, ownerAuth);
        LOG.info("TpmLinuxV20.collateIdentityRequest using EkHandle: {}", String.format("0x%08x", ekHandle));
        // existing akHandle so we can use it
        clearAkHandle(ownerAuth);

        ReadPublicResponse akPub;
        byte[] persistent = new byte[] { (byte) 0x81, 0x01, (byte) 0x80, 0x00 };
        try {
            byte[] nonceCaller = TpmUtils.createRandomBytes(20);
            StartAuthSessionResponse sasResponse = tpmNew.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            TPM_HANDLE eHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
            eHandle.AuthValue = ownerAuth;
            tpmNew.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            TPMS_SENSITIVE_CREATE inSensitive = new TPMS_SENSITIVE_CREATE(keyAuth, new byte[0]);

            TPMT_PUBLIC inPublic = new TPMT_PUBLIC(TPM_ALG_ID.SHA256,
                    new TPMA_OBJECT(TPMA_OBJECT.restricted, TPMA_OBJECT.userWithAuth, TPMA_OBJECT.sign,
                            TPMA_OBJECT.fixedTPM, TPMA_OBJECT.fixedParent, TPMA_OBJECT.sensitiveDataOrigin),
                    new byte[0],
                    new TPMS_RSA_PARMS(TPMT_SYM_DEF_OBJECT.nullObject(),
                            new TPMS_SIG_SCHEME_RSASSA(TPM_ALG_ID.SHA256),2048,65537),
                    new TPM2B_PUBLIC_KEY_RSA());

            CreateResponse cResponse = tpmNew._withSession(sasResponse.handle).Create(TPM_HANDLE.from(ekHandle),
                    inSensitive, inPublic, new byte[0], new TPMS_PCR_SELECTION[0]);
            tpmNew.FlushContext(sasResponse.handle);

            sasResponse = tpmNew.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            tpmNew.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            TPM_HANDLE loadHandle = tpmNew._withSession(sasResponse.handle).Load(TPM_HANDLE.from(ekHandle),
                    cResponse.outPrivate, cResponse.outPublic);
            tpmNew.FlushContext(sasResponse.handle);

            TPM_HANDLE oHandle = TPM_HANDLE.from(TPM_RH.OWNER);
            oHandle.AuthValue = ownerAuth;
            loadHandle.AuthValue = inSensitive.userAuth;
            tpmNew.EvictControl(oHandle, loadHandle,
                    TPM_HANDLE.fromTpm(persistent));
            tpmNew.FlushContext(loadHandle);

            akPub = tpmNew.ReadPublic(TPM_HANDLE.fromTpm(persistent));
        } catch (tss.TpmException e) {
            LOG.debug("TpmModule20.collateIdentityRequest failed to create ak");
            throw new Tpm.TpmException("TpmModule20.collateIdentityRequest failed to create ak");
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
        LOG.debug(" AIK Handle : {}", akHandle);

        byte[] recoveredSecret;
        try {
            byte[] nonceCaller = TpmUtils.createRandomBytes(20);
            StartAuthSessionResponse sasResponse = tpmNew.StartAuthSession(TPM_HANDLE.NULL, TPM_HANDLE.NULL,
                    nonceCaller, new byte[0], TPM_SE.POLICY,
                    TPMT_SYM_DEF.nullObject(), TPM_ALG_ID.SHA256);

            TPM_HANDLE eHandle = TPM_HANDLE.from(TPM_RH.ENDORSEMENT);
            eHandle.AuthValue = ownerAuth;
            tpmNew.PolicySecret(eHandle, sasResponse.handle,
                    new byte[0], new byte[0], new byte[0], 0);

            byte[] credential = proofRequest.getCredential();
            byte[] secret = proofRequest.getSecret();
            byte[] integrityHMAC = Arrays.copyOfRange(credential, 4, 4 + 32);
            byte[] encIdentity = Arrays.copyOfRange(credential,36, 36 + 18);
            secret = Arrays.copyOfRange(secret, 2, 2 + 256);
            TPMS_ID_OBJECT credentialBlob = new TPMS_ID_OBJECT(integrityHMAC, encIdentity);

            TPM_HANDLE aHandle = TPM_HANDLE.from(akHandle);
            aHandle.AuthValue = keyAuth;
            recoveredSecret = tpmNew._withSessions(TPM_HANDLE.pwSession(new byte[0]),
                    sasResponse.handle).ActivateCredential(aHandle, TPM_HANDLE.from(ekHandle), credentialBlob, secret);
            tpmNew.FlushContext(sasResponse.handle);
        } catch (tss.TpmException e) {
            throw new Tpm.TpmException("TpmLinuxV20.activateIdentity failed to activate credential");
        }

        try {
            return Utils.decryptSymCaAttestation(recoveredSecret, proofRequest.getSymBlob());
        } catch (BufferUnderflowException | Utils.SymCaDecryptionException ex) {
            LOG.debug("TpmLinuxV20.activateIdentity failed with exception", ex);
            throw new Tpm.TpmException("TpmLinuxV20.activateIdentity failed with exception", ex);
        }
    }

    @Override
    public int getAssetTagIndex() {
        return 0x01c10110;
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
    public String getTpmVersion() {
        return "2.0";
    }

    @Override
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<NVAttribute> attributes) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
        TPMA_NV nvAttributes = getTpmaNvFromAttributes(attributes);
        TPMS_NV_PUBLIC nvPub = new TPMS_NV_PUBLIC(nvHandle, TPM_ALG_ID.SHA256, nvAttributes, new byte[0], size);
        try {
            tpmNew.NV_DefineSpace(ownerHandle, indexPassword, nvPub);
        } catch (tss.TpmException e) {
            if (!e.getMessage().contains("NV_DEFINED")) {
                LOG.debug("TpmLinuxV20.nvDefine returned error {}", e.getMessage());
                throw new Tpm.TpmException("TpmLinuxV20.nvDefine returned error", e);
            }
        }
    }

    @Override
    public void nvRelease(byte[] ownerAuth, int index) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(TPM_RH.OWNER);
        ownerHandle.AuthValue = ownerAuth;
        TPM_HANDLE nvIndex = new TPM_HANDLE(index);
        tpmNew.NV_UndefineSpace(ownerHandle, nvIndex);
    }

    @Override
    public byte[] nvRead(byte[] authPassword, int index, int size) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(index);
        ownerHandle.AuthValue = authPassword;
        TPM_HANDLE nvIndex = new TPM_HANDLE(index);
        return tpmNew.NV_Read(ownerHandle, nvIndex,  size,  0);
    }

    @Override
    public void nvWrite(byte[] authPassword, int index, byte[] data) throws IOException, Tpm.TpmException {
        TPM_HANDLE ownerHandle = TPM_HANDLE.from(index);
        ownerHandle.AuthValue = authPassword;
        TPM_HANDLE nvHandle = new TPM_HANDLE(index);
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

        TPMS_PCR_SELECTION[] selectedPcrsToQuote = getTpmsPcrToQuoteSelections(pcrBanks, pcrs);
        TPM_HANDLE handle = TPM_HANDLE.from(ByteBuffer.wrap(aikBlob).order(ByteOrder.BIG_ENDIAN).getInt());
        handle.AuthValue = aikAuth;
        QuoteResponse quote;
        try {
            quote = tpmNew.Quote(handle, nonce, new TPMS_NULL_SIG_SCHEME(), selectedPcrsToQuote);
        } catch (tss.TpmException e) {
            throw new Tpm.TpmException("TpmLinuxV20.getQuote failed to generate quote");
        }

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
}
