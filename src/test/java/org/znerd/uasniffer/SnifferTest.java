// BSD-licensed, see COPYRIGHT file
// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import java.io.*;
import static org.znerd.util.text.TextUtils.quote;
import static org.znerd.util.text.TextUtils.isEmpty;
import static org.znerd.util.Preconditions.checkArgument;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

public class SnifferTest extends Object {

    private TestData _testData;

    @Before
    public void loadTestData() throws Exception {
        Class<?> clazz = getClass();
        InputStream byteStream = clazz.getResourceAsStream(clazz.getSimpleName() + "-input.txt");
        Reader charStream = new InputStreamReader(byteStream, "UTF-8");
        LineNumberReader lines = new LineNumberReader(charStream);

        _testData = new TestData(lines);
    }

    @Test
    public void testUserAgentSniffer() throws Exception {

        long start = System.currentTimeMillis();

        for (TestData.Entry entry : _testData.getEntries()) {
            String agentString = entry.getAgentString();
            UserAgent ua = Sniffer.analyze(agentString);

            // System.out.println(getClass().getSimpleName() + ": Sniffed in " + testDuration + " ms: " + agentString);

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

        long duration = System.currentTimeMillis() - start;
        int testCount = _testData.getEntries().size();
        double timePerTest = ((double) duration) / ((double) testCount);
        System.out.println(getClass().getSimpleName() + ": Performed " + testCount + " tests in " + duration + " ms (which is " + timePerTest + " ms per user agent sniff, on average).");
    }

    private static class TestData {

        TestData(LineNumberReader reader) throws IllegalArgumentException, IOException {

            _entries = new ArrayList<Entry>();

            // Process each line
            String line, agentString = null;
            List<String> outputStrings = new ArrayList<String>();
            while ((line = reader.readLine()) != null) {

                // Remove whitespace on both ends
                line = line.trim();

                // Empty line means: next entry;
                // if there is some data, store it and then reset
                if ("".equals(line)) {
                    if (agentString != null) {
                        _entries.add(new Entry(agentString, outputStrings));
                        agentString = null;
                        outputStrings = new ArrayList<String>();
                    }

                    // Ignore comments
                } else if (line.startsWith("#")) {
                    continue;

                    // First line or first line after empty line is the agent string
                } else if (agentString == null) {
                    agentString = line;

                    // Otherwise this is an expected output string
                } else {
                    outputStrings.add(line);
                }
            }

            // Add last entry, if any
            if (agentString != null) {
                _entries.add(new Entry(agentString, outputStrings));
            }
        }

        final Collection<Entry> _entries;

        public Collection<Entry> getEntries() {
            return _entries;
        }

        static class Entry {

            Entry(String agentString, Collection<String> expectedOutputStrings) throws IllegalArgumentException {
                checkPreconditions(agentString, expectedOutputStrings);
                _outputStrings = copyAllOutputStrings(agentString, expectedOutputStrings);
                _agentString = agentString;
            }

            private void checkPreconditions(String agentString, Collection<String> expectedOutputStrings) {
                checkArgument(isEmpty(agentString), "agentString (" + quote(agentString) + ") is null or empty.");
                checkArgument(expectedOutputStrings == null, "outputStrings " + quote(expectedOutputStrings) + " == null (for agent string \"" + agentString + "\")");
            }
            
            private final Collection<String> _outputStrings;

            private List<String> copyAllOutputStrings(String agentString, Collection<String> outputStrings) {
                List<String> result = new ArrayList<String>();
                for (String s : outputStrings) {
                    checkArgument(isEmpty(s), "One of the output strings is null or empty (for agent string \"" + agentString + "\")");
                    checkArgument(result.contains(s), "Found duplicate output string \"" + s + "\" (for agent string \"" + agentString + "\")");
                    result.add(s);
                }
                return result;
            }

            private final String _agentString;

            Collection<String> getOutputStrings() {
                return _outputStrings;
            }

            String getAgentString() {
                return _agentString;
            }
        }
    }
}
