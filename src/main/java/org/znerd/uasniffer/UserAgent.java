// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import java.util.HashSet;
import java.util.Set;

/**
 * Information about an analyzed user agent.
 * 
 * @author <a href="mailto:ernst@ernstdehaan.com">Ernst de Haan</a>
 */
public final class UserAgent {

   UserAgent(String agentString) throws IllegalArgumentException {
      if (agentString == null) {
         throw new IllegalArgumentException("agentString == null");
      }
      _string   = agentString;
      _stringLC = agentString.toLowerCase();
      _names    = new HashSet<String>();
   }

   private final String _string;
   private final String _stringLC;
   private final HashSet<String> _names;

   public String getAgentString() {
      return _string;
   }

   public String getLowerCaseAgentString() {
      return _stringLC;
   }

   public void addName(String name) {
      _names.add(name);
   }

   public Set<String> getNames() {
      return _names;
   }

   public boolean hasName(String name) {
      return _names.contains(name);
   }

   public void setBrowser(boolean b) {
   }

   public void setType(String t) {
   }

   public void setJavaScriptSupport(boolean b) {
   }

   public void setFlashSupport(boolean b) {
   }

   public void setTelProtocolSupport(boolean b) {
   }
}
