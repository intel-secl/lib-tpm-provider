/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.shell;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.exec.CommandLine;
import org.apache.commons.exec.DefaultExecutor;
import org.apache.commons.exec.Executor;
import org.apache.commons.exec.PumpStreamHandler;
import org.apache.commons.lang.ArrayUtils;

/**
 *
 * @author dczech
 */
public class TpmTool extends CommandLine {
    /**
     *
     * @param executable
     */
    public TpmTool(String executable) {
        super(executable);
    }
    
    private static String findExecutable(String binPath, String executable) {
        if(binPath == null || binPath.isEmpty()) {
            return executable;
        } else {
            return  Paths.get(binPath, executable).toString();
        }
    }
    
    /**
     *
     * @param binPath
     * @param executable
     */
    public TpmTool(String binPath, String executable) {
        super(findExecutable(binPath, executable));
    }

    /**
     *
     * @param tool
     */
    public TpmTool(CommandLine tool) {
        super(tool);
    }
    
    /**
     *
     * @return
     * @throws IOException
     */
    public final CommandLineResult execute() throws IOException {
        return this.execute(new HashMap<>());
    }
    // TODO: Remove loggers after testing
    /**
     *
     * @param environment
     * @return
     * @throws IOException
     */
    public CommandLineResult execute(Map<String, String> environment) throws IOException {
        Executor e = new DefaultExecutor();
        e.setExitValues(null);
        ByteArrayOutputStream stdOut = new ByteArrayOutputStream();
        ByteArrayOutputStream stdErr = new ByteArrayOutputStream();
        e.setStreamHandler(new PumpStreamHandler(stdOut, stdErr));
        int returnCode = e.execute(this, environment);
        return new CommandLineResult(returnCode, stdOut.toString(), stdErr.toString());
    }
}
