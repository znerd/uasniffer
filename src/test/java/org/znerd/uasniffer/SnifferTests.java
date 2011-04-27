// BSD-licensed, see COPYRIGHT file
// Copyright 2011, Ernst de Haan
package org.znerd.uasniffer;

import java.io.*;
import java.util.*;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * Tests for the <code>Sniffer</code> class.
 *
 * @author <a href="mailto:ernst@ernstdehaan.com">Ernst de Haan</a>
 */
public class SnifferTests extends Object {

   private static boolean isEmpty(String s) {
      return s == null || s.length() < 1;
   }

   private static String quote(Object obj) {
      if (obj == null) {
         return "(null)";
      } else {
         return "\"" + obj.toString() + '"';
      }
   }

   private TestData _testData;

   @Before
   public void loadTestData() throws Exception {
      InputStream byteStream = getClass().getResourceAsStream("SnifferTests-input.txt");
      Reader      charStream = new InputStreamReader(byteStream, "UTF-8");
      LineNumberReader lines = new LineNumberReader(charStream);

      _testData = new TestData(lines);
   }

   @Test
   public void testUserAgentSniffer() throws Exception {

      long start = System.currentTimeMillis();

      long     maxTestDuration = -0L;
      String maxTestDurationUA = null;
      for (TestData.Entry entry : _testData.getEntries()) {
         String agentString = entry.getAgentString();

         long    testStart = System.currentTimeMillis();
         UserAgent      ua = Sniffer.analyze(agentString);
         long testDuration = System.currentTimeMillis() - testStart;

         // System.out.println(getClass().getSimpleName() + ": Sniffed in " + testDuration + " ms: " + agentString);

         if (testDuration > maxTestDuration) {
            maxTestDuration   = testDuration;
            maxTestDurationUA = agentString;
         }

         assertEquals(agentString,               ua.getAgentString()         );
         assertEquals(agentString.toLowerCase(), ua.getLowerCaseAgentString());

         // Find all recognized names
         Collection<String> actualNames = ua.getNames();

         // Compare expected and recognized
         Collection<String> actualNames2 = new HashSet<String>(actualNames);
         for (String expectedName : entry.getOutputStrings()) {
            if (actualNames.contains(expectedName)) {
               actualNames.remove(expectedName);
            } else if (expectedName.startsWith("BrowserLocale-")) {
               // skip (TODO)
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

      long      duration = System.currentTimeMillis() - start;
      int      testCount = _testData.getEntries().size();
      double timePerTest = ((double) duration) / ((double) testCount);
      System.out.println(getClass().getSimpleName() + ": Performed " + testCount + " tests in " + duration + " ms (which is " + timePerTest + " ms per user agent sniff, on average). Max duration was " + maxTestDuration + " ms, for user agent: \"" + maxTestDurationUA + "\".");
   }


   //-------------------------------------------------------------------------
   // Inner classes
   //-------------------------------------------------------------------------

   private static class TestData {

      //----------------------------------------------------------------------
      // Constructors
      //----------------------------------------------------------------------

      TestData(LineNumberReader reader)
      throws IllegalArgumentException, IOException {

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
                  agentString   = null;
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


      //----------------------------------------------------------------------
      // Fields
      //----------------------------------------------------------------------

      Collection<Entry> _entries;


      //----------------------------------------------------------------------
      // Methods
      //----------------------------------------------------------------------

      public Collection<Entry> getEntries() {
         return _entries;
      }


      //----------------------------------------------------------------------
      // Inner classes
      //----------------------------------------------------------------------

      static class Entry {

         //-------------------------------------------------------------------
         // Constructors
         //-------------------------------------------------------------------

         /**
          * Constructs a new <code>Entry</code>.
          *
          * @param agentString
          *    the user agent string, cannot be <code>null</code> nor empty.
          *
          * @param outputStrings
          *    the expected output strings, cannot be <code>null</code>,
          *    cannot be empty and cannot contain any <code>null</code>, empty
          *    or duplicate elements.
          *
          * @throws IllegalArgumentException
          *    if any of the preconditions failed.
          */
         Entry(String agentString, Collection<String> outputStrings)
         throws IllegalArgumentException {

            // Check preconditions
            if (isEmpty(agentString)) {
               throw new IllegalArgumentException("agentString (" + quote(agentString) + ") is null or empty.");
            } else if (outputStrings == null) {
               throw new IllegalArgumentException("outputStrings " + quote(outputStrings) + " == null (for agent string \"" + agentString + "\")");
            }

            // Copy all output strings
            _outputStrings = new ArrayList<String>();
            for (String s : outputStrings) {
               if (isEmpty(s)) {
                  throw new IllegalArgumentException("One of the output strings is null or empty (for agent string \"" + agentString + "\")");
               } else if (_outputStrings.contains(s)) {
                  throw new IllegalArgumentException("Found duplicate output string \"" + s + "\" (for agent string \"" + agentString + "\")");
               }
               _outputStrings.add(s);
            }

            // Store the agent string
            _agentString = agentString;
         }


         //-------------------------------------------------------------------
         // Fields
         //-------------------------------------------------------------------

         private final String _agentString;
         private final Collection<String> _outputStrings;


         //-------------------------------------------------------------------
         // Methods
         //-------------------------------------------------------------------

         String getAgentString() {
            return _agentString;
         }

         Collection<String> getOutputStrings() {
            return _outputStrings;
         }
      }
   }
}
