/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.shell;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Map;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.Executor;
import org.apache.commons.exec.PumpStreamHandler;

/**
 *
 * @author dczech
 */
public class TpmToolNiarl extends TpmTool {
    private final int mode;
    private final boolean useTrousers;

    /**
     *
     * @param binPath
     * @param mode
     * @param useTrousers
     */
    public TpmToolNiarl(String binPath, int mode, boolean useTrousers) {
        super(Paths.get(binPath, "NIARL_TPM_Module").toString());
        this.mode = mode;
        this.useTrousers = useTrousers;
    }
    
    /**
     *
     * @param environment
     * @return
     * @throws IOException
     */
    @Override
    public CommandLineResult execute(Map<String, String> environment) throws IOException {
        String[] args = getArguments();
        CommandLine clone = new CommandLine(this.getExecutable());
        for(int i = 0; i < args.length; i++) {
            String arg = args[i];
            clone.addArgument(arg);
            if(arg.equals("-owner_auth") || arg.equals("-nonce") || arg.equals("-key_auth")
                    || arg.equals("-pcak") || arg.equals("-blob_auth")) {
                String envVarName = arg.substring(1).toUpperCase();
                // insert the next argument, and increment the counter so we dont check it on next loop
                environment.put(envVarName, args[++i]);
                clone.addArgument(envVarName);
            }
        }
        // Make a clone of command line so we can add new arguments to it
        clone.addArgument("-t");
        clone.addArgument("-mode");
        clone.addArgument(Integer.toString(mode));
        if(useTrousers) {
            clone.addArgument("-trousers");
        }
        Executor e = new DefaultExecutor();
        e.setExitValues(null);
        ByteArrayOutputStream stdOut = new ByteArrayOutputStream();
        ByteArrayOutputStream stdErr = new ByteArrayOutputStream();
        e.setStreamHandler(new PumpStreamHandler(stdOut, stdErr));
        int returnCode = e.execute(clone, environment);
        return new CommandLineResult(returnCode, stdOut.toString(), stdErr.toString());
    }
    
}
