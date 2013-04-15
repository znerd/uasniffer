// BSD-licensed, see COPYRIGHT file
// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import static org.znerd.util.test.TestUtils.testUtilityClassConstructor;

import org.junit.Test;

public class SnifferUtilityClassTest {
    @Test
    public void testUtilityConstructor() throws Exception {
        testUtilityClassConstructor(Sniffer.class);
    }
}
