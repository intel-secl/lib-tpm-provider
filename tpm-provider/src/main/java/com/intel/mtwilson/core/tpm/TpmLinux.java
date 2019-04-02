/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.io.FileUtils;

/**
 *
 * @author dczech
 */
abstract class TpmLinux extends Tpm {

    private final static org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TpmLinux.class);

    TpmLinux() {
        super();
    }

    TpmLinux(String tpmToolsPath) {
        super(tpmToolsPath);
    }

    /**
     *
     * @return @throws IOException
     * @throws TpmException
     */
    @Override
    public String getModuleLog() throws IOException, TpmException {
        File measureLogFile = Paths.get("/opt", "trustagent", "var", "measureLog.xml").toFile();
        String content;
        if (measureLogFile.exists()) {
            content = FileUtils.readFileToString(measureLogFile);
        } else {
            File outFile = null;
            try {
                outFile = File.createTempFile("measureLog", ".xml");
                Map<String, String> variables = new HashMap<>();
                variables.put("OUTFILE", outFile.getAbsolutePath());
                TpmTool command = new TpmTool(getTpmToolsPath(), "module_analysis.sh");
                CommandLineResult result = command.execute(variables);
                if (result.getReturnCode() != 0) {
                    LOG.debug("Error running command [{}]: {}", command.getExecutable(), result.getStandardError());
                    throw new TpmException("TpmLinux.getModuleLog module_analysis.sh returned nonzero error", result.getReturnCode());
                }
                LOG.debug("command stdout: {}", result.getStandardOut());
                content = FileUtils.readFileToString(outFile);
            } catch (TpmException ex) {
                throw new TpmException(ex);
            } catch (IOException ex) {
                throw new IOException(ex);
            } finally {
                if (outFile!=null) {
                    boolean deletedOutFile = outFile.delete();
                    if (!deletedOutFile) {
                        outFile.deleteOnExit();
                    }
                }
            }
        }
        return getModulesFromMeasureLogXml(content);
    }

    private String tcbMeasurementPath;

    /**
     * Sets the of the Tcb Measurement so it can be easily retrieved with {@link #getTcbMeasurement()
     * } down the line.
     *
     * @param path
     */
    public void setTcbMeasurementPath(String path) {
        tcbMeasurementPath = path;
    }

    /**
     *
     * @return @throws IOException
     * @throws TpmException
     */
    @Override
    public String getTcbMeasurement() throws IOException, TpmException {
        File tcbMeasurementFile = Paths.get("/opt", "trustagent", "var", "measureLog.xml").toFile();
        if (tcbMeasurementFile.exists()) {
            return FileUtils.readFileToString(tcbMeasurementFile, Charset.forName("UTF-8"));
        } else {
            LOG.debug("TpmLinux.getTcbMeasurement measurement.xml does not exist");
            throw new TpmTcbMeasurementMissingException("TpmLinux.getTcbMeasurement measurement.xml does not exist");
        }
    }
}
