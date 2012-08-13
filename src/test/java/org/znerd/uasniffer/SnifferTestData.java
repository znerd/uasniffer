// BSD-licensed, see COPYRIGHT file
// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import java.io.IOException;
import java.io.LineNumberReader;
import java.util.ArrayList;
import java.util.List;

import org.znerd.util.test.junit.PolySuite;

public class SnifferTestData implements PolySuite.Configuration {
    private final List<SnifferTestDataEntry> entries;

    public SnifferTestData(LineNumberReader lines) throws IOException {
        entries = new ArrayList<SnifferTestDataEntry>();

        // Process each line
        String line, agentString = null;
        List<String> outputStrings = new ArrayList<String>();
        while ((line = lines.readLine()) != null) {

            // Remove whitespace on both ends
            line = line.trim();

            // Empty line means: next entry;
            // if there is some data, store it and then reset
            if ("".equals(line)) {
                if (agentString != null) {
                    entries.add(new SnifferTestDataEntry(agentString, outputStrings));
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
            entries.add(new SnifferTestDataEntry(agentString, outputStrings));
        }
    }

    @Override
    public int size() {
        return entries.size();
    }

    @Override
    public Object getTestValue(int index) {
        return entries.get(index);
    }

    @Override
    public String getTestName(int index) {
        return entries.get(index).getAgentString();
    }
}
