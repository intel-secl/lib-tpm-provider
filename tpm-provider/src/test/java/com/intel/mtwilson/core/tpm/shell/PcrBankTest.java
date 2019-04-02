/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.shell;

import com.intel.mtwilson.core.tpm.Tpm.PcrBank;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author david
 */
public class PcrBankTest {
    
    public PcrBankTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }
    
    @Test
    public void testPcrBanks() {
        Set<PcrBank> set = new HashSet<>();
        set.add(PcrBank.SHA1);
        set.add(PcrBank.SHA256);
        String blah = set.stream().sorted().map(PcrBank::toString).collect(Collectors.joining(" "));
        assertEquals(blah, "SHA1 SHA256");
    }
}
