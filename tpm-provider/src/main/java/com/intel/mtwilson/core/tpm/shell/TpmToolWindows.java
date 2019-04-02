/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.shell;

import java.nio.file.Paths;

/**
 *
 * @author dczech
 */
public final class TpmToolWindows extends TpmTool {
    
    /**
     *
     * @param binPath
     * @param command
     */
    public TpmToolWindows(String binPath, String command) {
        super(Paths.get(binPath, "TPMTool.exe").toString());
        addArgument(command);
    }
    
}
