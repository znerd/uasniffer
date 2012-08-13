// Copyright 2011, Ernst de Haan
// BSD-licensed, see COPYRIGHT file
package org.znerd.uasniffer;

import static org.znerd.util.Preconditions.checkArgument;
import static org.znerd.util.text.TextUtils.isEmpty;
import static org.znerd.util.text.TextUtils.quote;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class SnifferTestDataEntry {

    private final String _agentString;

    public SnifferTestDataEntry(String agentString, Collection<String> expectedOutputStrings) throws IllegalArgumentException {
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

    public Collection<String> getOutputStrings() {
        return _outputStrings;
    }

    public String getAgentString() {
        return _agentString;
    }
}
