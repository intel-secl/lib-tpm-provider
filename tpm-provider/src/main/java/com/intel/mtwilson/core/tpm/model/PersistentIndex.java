/*
 * Copyright (C) 2019 Intel Corporation
 * All rights reserved.
 */

package com.intel.mtwilson.core.tpm.model;
/**
 *
 * @author ddhawale
 */
public enum PersistentIndex {
    PK(0x81000000),
    EK(0x81010000),
    AIK(0x81018000);

    private int value;

    PersistentIndex(int value) {
        this.value = value;
    }

    public int getValue() {
        return value;
    }
}
