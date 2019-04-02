/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.shell;

import java.util.HashMap;
import java.util.Map;
import org.apache.commons.lang3.SystemUtils;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;
import static org.junit.Assume.assumeTrue;

/**
 *
 * @author david
 */
public class TpmToolTest {

    public TpmToolTest() {
    }

    @BeforeClass
    public static void setUpClass() {
    }

    @AfterClass
    public static void tearDownClass() {
    }

    @Before
    public void setUp() {
        assumeTrue(SystemUtils.IS_OS_LINUX);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of execute method, of class TpmTool.
     */
    @Test
    public void testExecute() throws Exception {
        System.out.println("execute");
        TpmTool instance = new TpmTool("", "echo");
        instance.addArgument("foobar");
        CommandLineResult result = instance.execute();
        assertTrue(result.getReturnCode() == 0);
        assertTrue(result.getStandardOut().contains("foobar"));
    }

    /**
     * Test of execute method, of class TpmTool.
     */
    @Test
    public void testExecute_Map() throws Exception {
        System.out.println("execute");
        Map<String, String> environment = new HashMap<>();
        environment.put("FOO", "bar");
        TpmTool instance = new TpmTool("printenv");
        instance.addArgument("FOO");
        CommandLineResult result = instance.execute(environment);
        assertTrue(result.getReturnCode() == 0);
        System.out.println(result.getStandardOut());
        assertTrue(result.getStandardOut().contains("bar"));
    }

    @Test
    public void testExecute_Null() throws Exception {
        TpmTool instance = new TpmTool(null, "echo");
        instance.addArgument("foobar");
        CommandLineResult result = instance.execute();
        assertTrue(result.getReturnCode() == 0);
        assertTrue(result.getStandardOut().contains("foobar"));
    }

}
