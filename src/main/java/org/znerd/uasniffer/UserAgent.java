// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

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
   }

   public String getAgentString() {
      return null;
   }

   public String getLowerCaseAgentString() {
      return null;
   }

   public void addName(String name) {
   }

   public boolean hasName(String name) {
      return false;
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
