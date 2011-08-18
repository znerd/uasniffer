// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import java.util.HashSet;
import java.util.Set;

import org.znerd.util.Preconditions;

/**
 * Information about an analyzed user agent, as a set of names.
 * <p>
 * For example, Internet Explorer 7 has used agent strings like this: <blockquote><code>Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)</code></blockquote>
 * <p>
 * This could result in the following names in a <code>UserAgent</code> object:
 * <ul>
 * <li>Device-Desktop
 * <li>Device-NoPhone
 * <li>Browser-MSIE
 * <li>Browser-DesktopMSIE
 * <li>Browser-DesktopMSIE-7
 * <li>Browser-DesktopMSIE-7-0
 * <li>Browser-DesktopMSIE-7-0-0
 * <li>BrowserEngine-Trident
 * <li>BrowserOS-Windows
 * <li>BrowserOS-Windows-NT
 * <li>BrowserOS-Windows-NT-6
 * <li>BrowserOS-Windows-NT-6-0
 * <li>BrowserOS-Windows-Vista
 * </ul>
 */
public final class UserAgent {

    UserAgent(String agentString) throws IllegalArgumentException {
        Preconditions.checkArgument(agentString == null, "agentString == null");
        _names = new HashSet<String>();
        _string = agentString;
        _stringLC = agentString.toLowerCase();
    }

    private final HashSet<String> _names;
    private final String _string;
    private final String _stringLC;

    @Override
    public String toString() {
        return _string;
    };

    String getLowerCaseAgentString() {
        return _stringLC;
    }

    /**
     * Returns the agent string that was used to create this object. That string is also returned from {@link #toString()}.
     * 
     * @return the original agent string, never <code>null</code>.
     */
    public String getAgentString() {
        return _string;
    }

    void addName(String name) {
        _names.add(name);
    }

    /**
     * Retrieves all names associated with this user agent.
     * 
     * @return a {@link Set} of all names associated with this user agent.
     */
    public Set<String> getNames() {
        return _names;
    }

    /**
     * Determines if the specified name is associated with this user agent.
     * 
     * @param name the name to check; if <code>name == null</code> then <code>false</code> is returned.
     * @return <code>true</code> if the name is associated with this object, <code>false</code> otherwise.
     */
    public boolean hasName(String name) {
        return name == null ? false : _names.contains(name);
    }

    /**
     * Returns all names associated with this user agent, separated by a single space each, in random order.
     * 
     * @return all names, separated by a space character; never <code>null</code>.
     */
    public String getNamesAsString() {
        String s = "";
        for (String name : _names) {
            s += " " + name;
        }
        return "".equals(s) ? s : s.substring(1);
    }
}
