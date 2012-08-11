// BSD-licensed, see COPYRIGHT file
// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.Reader;
import java.util.Collection;
import java.util.HashSet;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.znerd.util.test.junit.PolySuite;

@RunWith(PolySuite.class)
public class SnifferTest extends Object {

    private final SnifferTestDataEntry entry;

    public SnifferTest(SnifferTestDataEntry entry) {
        this.entry = entry;
    }

    @PolySuite.Config
    public static SnifferTestData loadTestData() throws Exception {
        Class<?> clazz = SnifferTest.class;
        InputStream byteStream = clazz.getResourceAsStream(clazz.getSimpleName() + "-input.txt");
        Reader charStream = new InputStreamReader(byteStream, "UTF-8");
        LineNumberReader lines = new LineNumberReader(charStream);

        return new SnifferTestData(lines);
    }

    @Test
    public void testUserAgentSniffer() throws Exception {
        String agentString = entry.getAgentString();
        UserAgent ua = Sniffer.analyze(agentString);

        assertEquals(agentString, ua.getAgentString());
        assertEquals(agentString.toLowerCase(), ua.getLowerCaseAgentString());

        // Find all recognized names
        Collection<String> actualNames = ua.getNames();

        // Compare expected and recognized
        Collection<String> actualNames2 = new HashSet<String>(actualNames);
        for (String expectedName : entry.getOutputStrings()) {
            if (actualNames.contains(expectedName)) {
                actualNames.remove(expectedName);
            } else {
                String message = "For agent string \"" + agentString + "\": Missing expected name \"" + expectedName + "\".";
                System.out.println(message);
                for (String name : actualNames2) {
                    System.out.println("-- did find name: " + name);
                }
                fail(message);
                throw new Error();
            }
        }

        // Some unexpected ones remain
        if (actualNames.size() > 0) {
            fail("For agent string \"" + agentString + "\": Found " + actualNames.size() + " unexpected name(s), like \"" + actualNames.iterator().next() + "\".");
        }
    }
}
