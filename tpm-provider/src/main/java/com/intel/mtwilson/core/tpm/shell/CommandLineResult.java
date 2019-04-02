/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.shell;

/**
 *
 * @author dczech
 */
public class CommandLineResult {

    private final int returnCode;
    private final String[] lastLineTokens;
    private final String lastLine;
    private final String standardOut;
    private final String standardError;

    /**
     *
     * @return
     */
    public String getStandardOut() {
        return standardOut;
    }

    /**
     *
     * @return
     */
    public String getStandardError() {
        return standardError;
    }

    /**
     *
     * @return
     */
    public int getReturnCode() {
        return returnCode;
    }

    /**
     *
     * @return
     */
    public String getLastLine() {
        return lastLine;
    }

    /**
     *
     * @return
     */
    public int getLastLineTokenCount() {
        return lastLineTokens.length;
    }

    /**
     *
     * @param index
     * @return
     */
    public String getLastLineToken(int index) {
        return lastLineTokens[index];
    }

    /**
     *
     * @param returnCode
     * @param standardOut
     * @param standardError
     */
    public CommandLineResult(int returnCode, String standardOut, String standardError) {
        this.returnCode = returnCode;
        this.standardOut = standardOut;
        this.standardError = standardError;

        String[] lines = standardOut.split(System.lineSeparator());
        if (lines.length > 0) {
            this.lastLine = lines[lines.length - 1]; // get last line
            this.lastLineTokens = lastLine.split("\\s");
        } else {
            this.lastLine = "";
            this.lastLineTokens = new String[0];
        }
    }
}
