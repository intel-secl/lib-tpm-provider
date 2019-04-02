/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.model;

/**
 * Model Object containing all of the relevant data for a Certified Key Deriving from the AIK
 * @author dczech
 */
public class CertifiedKey {
    private byte[] keyModulus;
    private byte[] keyBlob;
    private byte[] keySignature;
    private byte[] keyData;
    private byte[] keyName;

    /**
     *
     * @return
     */
    public byte[] getKeyName() {
        return keyName;
    }

    /**
     *
     * @param keyName
     */
    public void setKeyName(byte[] keyName) {
        this.keyName = keyName;
    }
    
    /**
     * Default Constructor
     */
    public CertifiedKey() {
        
    }

    /**
     *
     * @param keyModulus
     * @param keyBlob
     * @param keySignature
     * @param keyData
     */
    public CertifiedKey(byte[] keyModulus, byte[] keyBlob, byte[] keySignature, byte[] keyData) {
        this.keyModulus = keyModulus;
        this.keyBlob = keyBlob;
        this.keySignature = keySignature;
        this.keyData = keyData;
    }

    /**
     *
     * @return
     */
    public byte[] getKeyModulus() {
        return keyModulus;
    }

    /**
     *
     * @param keyModulus
     */
    public void setKeyModulus(byte[] keyModulus) {
        this.keyModulus = keyModulus;
    }

    /**
     *
     * @return
     */
    public byte[] getKeyBlob() {
        return keyBlob;
    }

    /**
     *
     * @param keyBlob
     */
    public void setKeyBlob(byte[] keyBlob) {
        this.keyBlob = keyBlob;
    }

    /**
     *
     * @return
     */
    public byte[] getKeySignature() {
        return keySignature;
    }

    /**
     *
     * @param keySignature
     */
    public void setKeySignature(byte[] keySignature) {
        this.keySignature = keySignature;
    }

    /**
     *
     * @return
     */
    public byte[] getKeyData() {
        return keyData;
    }

    /**
     *
     * @param keyData
     */
    public void setKeyData(byte[] keyData) {
        this.keyData = keyData;
    }
}
