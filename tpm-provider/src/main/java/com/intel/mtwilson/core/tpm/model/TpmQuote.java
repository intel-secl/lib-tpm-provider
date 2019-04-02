/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.model;

import com.intel.mtwilson.core.tpm.Tpm.PcrBank;
import java.util.Set;

/**
 *
 * @author dczech
 */
public class TpmQuote {
    private long timestamp;
    private Set<PcrBank> pcrBanks;
    private byte[] quoteData;

    /**
     * Default Constructor
     */
    public TpmQuote() {

    }

    /**
     * Constructor with Args
     * @param timestamp
     * @param pcrBanks
     * @param quoteData
     */
    public TpmQuote(long timestamp, Set<PcrBank> pcrBanks, byte[] quoteData) {
        this.timestamp = timestamp;
        this.pcrBanks = pcrBanks;
        this.quoteData = quoteData;
    }

    /**
     *
     * @return
     */
    public long getTimestamp() {
        return timestamp;
    }

    /**
     *
     * @param timestamp
     */
    public void setTimestamp(long timestamp) {
        this.timestamp = timestamp;
    }

    /**
     *
     * @return
     */
    public Set<PcrBank> getPcrBanks() {
        return pcrBanks;
    }

    /**
     *
     * @param pcrBanks
     */
    public void setPcrBanks(Set<PcrBank> pcrBanks) {
        this.pcrBanks = pcrBanks;
    }

    /**
     *
     * @return
     */
    public byte[] getQuoteData() {
        return quoteData;
    }

    /**
     *
     * @param quoteData
     */
    public void setQuoteData(byte[] quoteData) {
        this.quoteData = quoteData;
    }

}
