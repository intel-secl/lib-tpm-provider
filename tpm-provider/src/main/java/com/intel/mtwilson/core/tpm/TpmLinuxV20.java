/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import tss.TpmDeviceBase;

import java.io.IOException;

/**
 *
 * @author dczech
 */
class TpmLinuxV20 extends TpmV20 {
    TpmLinuxV20(TpmDeviceBase base) {
        super(base);
    }

    @Override
    public String getModuleLog() throws IOException, TpmException {
        return new TpmLinuxV12(null).getModuleLog();
    }

    @Override
    public String getTcbMeasurement() throws IOException, TpmException {
        return new TpmLinuxV12(null).getTcbMeasurement();
    }
}
