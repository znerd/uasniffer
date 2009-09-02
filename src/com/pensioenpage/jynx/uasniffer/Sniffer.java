// Copyright 2007-2009, PensioenPage B.V.
package com.pensioenpage.jynx.uasniffer;

import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

import org.xins.common.MandatoryArgumentChecker;
import org.xins.common.xml.Element;

/**
 * User agent sniffer.
 * 
 * @version $Revision: 10153 $ $Date: 2009-08-24 12:22:25 +0200 (ma, 24 aug 2009) $
 * @author <a href="mailto:anthony.goubard@japplis.com">Anthony Goubard</a>
 * @author <a href="mailto:mees@wittemansoftware.nl">Mees Witteman</a>
 * @author <a href="mailto:ernst@pensioenpage.com">Ernst de Haan</a>
 */
public final class UserAgentSniffer extends Object {

   //-------------------------------------------------------------------------
   // Class fields
   //-------------------------------------------------------------------------

   /**
    * An instance of this class, to avoid that the unit test coverage
    * complains about the constructor not being called.
    */
   private static final Object FOOL_COVERAGE = new UserAgentSniffer();


   //-------------------------------------------------------------------------
   // Class functions
   //-------------------------------------------------------------------------

   /**
    * Builds an XML element that describes the user agent.
    *
    * @param agentString
    *    the user agent string, or <code>null</code>.
    *
    * @return
    *    an XML {@link Element} that describes the user agent,
    *    never <code>null</code>.
    *
    * @throws IllegalArgumentException
    *    if <code>agentString == null</code>.
    */
   public static final Element buildElement(String agentString)
   throws IllegalArgumentException {

      // Check preconditions
      MandatoryArgumentChecker.check("agentString", agentString);

      Set<String> names = new HashSet<String>();

      // Convert the User-Agent request header to lower case
      String ua = agentString.toLowerCase();

      // Detect specific devices
      boolean    android = ua.contains("android");
      boolean appleTouch = ua.contains("ipod") || ua.contains("iphone");

      // Mobile devices
      boolean          matchFound = false;
      String               uaType = "desktop";
      boolean supportsTelProtocol = false;
      boolean     supportsScripts = true;
      boolean       supportsFlash = true;
      boolean           isBrowser = true;
      for (int i=0; i < UA_MOBILE_DEVICE_SNIPPETS.length; i++) {
         if (ua.contains(UA_MOBILE_DEVICE_SNIPPETS[i])) {
            matchFound          = true;
            uaType              = "mobile";
            supportsTelProtocol = true;
            supportsScripts     = false;
            supportsFlash       = false;

            for (int j=0; j < UA_MOBILE_DEVICE_WITHOUT_TEL_SUPPORT.length; j++) {
               if (ua.contains(UA_MOBILE_DEVICE_WITHOUT_TEL_SUPPORT[j])) {
                  supportsTelProtocol = false;
               }
            }
         }
      }

      // iPod
      if (!matchFound && ua.contains("ipod")) {
         matchFound          = true;
         uaType              = "desktop";
         supportsTelProtocol = false;
         supportsScripts     = true;
         supportsFlash       = false;

      // iPhone
      } else if (!matchFound && ua.contains("iphone")) {
         matchFound          = true;
         uaType              = "desktop";
         supportsTelProtocol = true;
         supportsScripts     = true;
         supportsFlash       = false;

      // Android
      } else if (!matchFound && ua.contains("android")) {
         matchFound          = true;
         uaType              = "desktop";
         supportsTelProtocol = true;
         supportsScripts     = true;
         supportsFlash       = false;

      // Palm Pre
      } else if (!matchFound && ua.contains("pre/")) {
         matchFound          = true;
         uaType              = "desktop";
         supportsTelProtocol = true;
         supportsScripts     = true;
         supportsFlash       = false;

      // Bots
      } else if (!matchFound) {
         for (int i=0; i < UA_BOT_SNIPPETS.length; i++) {
            if (ua.contains(UA_BOT_SNIPPETS[i])) {
               matchFound          = true;
               uaType              = "bot";
               supportsTelProtocol = false;
               supportsScripts     = false;
               supportsFlash       = false;
               isBrowser           = false;
            }
         }
      }

      Element element = new Element("UserAgent");
      element.setAttribute("string",  agentString);
      element.setAttribute("browser", String.valueOf(isBrowser));
      element.setAttribute("type",    uaType);

      // Support for the "tel:" protocol
      Element suppElement = new Element("Support");
      suppElement.setAttribute("technology", "TelProtocol");
      suppElement.setAttribute("supported",  Boolean.toString(supportsTelProtocol));
      element.addChild(suppElement);

      // Support for JavaScript
      suppElement = new Element("Support");
      suppElement.setAttribute("technology", "ECMAScript");
      suppElement.setAttribute("supported",  Boolean.toString(supportsScripts));
      element.addChild(suppElement);

      // Support for Adobe Flash
      suppElement = new Element("Support");
      suppElement.setAttribute("technology", "Flash");
      suppElement.setAttribute("supported",  Boolean.toString(supportsFlash));
      element.addChild(suppElement);

      // Categorize Device
      if (supportsTelProtocol) {
         names.add("Device-Phone");
      } else {
         names.add("Device-NoPhone");
      }
      if ("mobile".equals(uaType) || appleTouch || android || ua.contains("webos/")) {
         names.add("Device-Mobile");
      } else if ("bot".equals(uaType)) {
         names.add("Device-Bot");
      } else {
         names.add("Device-Desktop");
      }
      if (appleTouch) {
         names.add("Device-AppleTouch");
         if (ua.contains("ipod")) {
            names.add("Device-AppleTouch-iPod");
         } else { // iPhone
            names.add("Device-AppleTouch-iPhone");
         }
      } else if (ua.contains("blackberry")) {
         analyze(ua, names, "Device-Blackberry", "blackberry", 1, false);
      }

      // Detect OS, browser engine and browser
      if (! "bot".equals(uaType)) {
         detectOS           (ua, names);
         detectBrowserEngine(ua, names);
         detectBrowser      (ua, names);
      }

      for (String name : names) {
         Element nameElement = new Element("Recognized");
         nameElement.setAttribute("name", name);
         element.addChild(nameElement);
      }

      return element;
   }

   private static final void detectOS(String ua, Set<String> names) {

      // Linux
      if (ua.contains("linux")) {
         addName(names, "BrowserOS-NIX");
         addName(names, "BrowserOS-Linux");
         if (ua.contains("linux 2.")) {
            analyze(ua, names, "BrowserOS-Linux", "linux ");
         }

         // Android
         if (ua.contains("android")) {
            analyze(ua, names, "BrowserOS-Linux-Android", "android ");
         }

      // webOS, by Palm
      } else if (ua.contains("webos/")) {
         analyze(ua, names, "BrowserOS-WebOS", "webos/");

      // iPhone OS (detect before Mac OS)
      } else if (ua.contains("iphone") || ua.contains("ipod")) {
         analyze(ua.replace('_', '.'), names, "BrowserOS-iPhoneOS", "iPhone OS ");

      // Mac OS
      } else if (ua.contains("mac os") || ua.contains("mac_") || ua.contains("macintosh")) {

         addName(names, "BrowserOS-MacOS");

         // Mac OS X
         if (ua.contains("mac os x")) {
            addName(names, "BrowserOS-NIX");
            addName(names, "BrowserOS-MacOS-10");
            analyze(ua.replace('_', '.'), names, "BrowserOS-MacOS", "mac os x ",              0, false);
            analyze(ua.replace('_', '.'), names, "BrowserOS-MacOS", "mac os x tiger ",        0, false);
            analyze(ua.replace('_', '.'), names, "BrowserOS-MacOS", "mac os x leopard ",      0, false);
            analyze(ua.replace('_', '.'), names, "BrowserOS-MacOS", "mac os x snow leopard ", 0, false);
         }

      // Windows
      } else if (ua.contains("windows") || ua.contains("win3.") || ua.contains("win9") || ua.contains("winnt") || ua.contains("wince")) {
         addName(names, "BrowserOS-Windows");
         if (ua.contains("windows nt")) {
            analyze(ua, names, "BrowserOS-Windows-NT", "windows nt ", 2, true);
         } else if (ua.contains("windows 5.") || ua.contains("windows 6.")) {
            analyze(ua, names, "BrowserOS-Windows-NT", "windows ", 2, false);
         } else if (ua.contains("windows vista")) {
            analyze("nt/6.0", names, "BrowserOS-Windows-NT", "nt/", 2, false);
         } else if (ua.contains("windows xp")) {
            analyze("nt/5.1", names, "BrowserOS-Windows-NT", "nt/", 2, false);
         } else if (ua.contains("windows 2000")) {
            analyze("nt/5.0", names, "BrowserOS-Windows-NT", "nt/", 2, false);
         } else if (ua.contains("winnt")) {
            analyze(ua, names, "BrowserOS-Windows-NT", "winnt", 2, true);

         // Windows ME (needs to be checked before Windows 98)
         } else if (ua.contains("win 9x 4.90") || ua.contains("windows me")) {
            addName(names, "BrowserOS-Windows-ME");

         // Windows 98
         } else if (ua.contains("windows 98") || ua.contains("win98")) {
            addName(names, "BrowserOS-Windows-98");

         // Windows 95
         } else if (ua.contains("windows 95") || ua.contains("win95")) {
            addName(names, "BrowserOS-Windows-95");

         // Windows Mobile
         } else if (ua.contains("windows mobile") || ua.contains("windows; ppc") || ua.contains("windows ce") || ua.contains("wince")) {
            analyze(ua, names, "BrowserOS-Windows-Mobile", "windows mobile ", 3, true);

         // Windows 3.x
         } else if (ua.contains("windows 3.")) {
            analyze(ua, names, "BrowserOS-Windows", "windows ", 3, true);
         } else if (ua.contains("win3.")) {
            int    indexWin3 = ua.indexOf("win3.");
            int indexWindows = ua.indexOf("windows");
            String         s = (indexWindows >= 0 && indexWindows < indexWin3) ? ua.substring(indexWindows + 1) : ua;

            analyze(s, names, "BrowserOS-Windows", "win", 3, true);
         }

         // Add some marketing names for various Windows versions
         if (names.contains("BrowserOS-Windows-NT-5-0")) {
            addName(names, "BrowserOS-Windows-2000");
         } else if (names.contains("BrowserOS-Windows-NT-5")) {
            addName(names, "BrowserOS-Windows-XP");
         } else if (names.contains("BrowserOS-Windows-NT-6-0")) {
            addName(names, "BrowserOS-Windows-Vista");
         } else if (names.contains("BrowserOS-Windows-NT-6-1")) {
            addName(names, "BrowserOS-Windows-7");
         }

      // DragonFlyBSD, extra check
      } else if (ua.contains("dragonfly")) {
         addName(names, "BrowserOS-NIX");
         addName(names, "BrowserOS-BSD");
         addName(names, "BrowserOS-BSD-DragonFlyBSD");

      // Other BSD variants
      } else if (ua.contains("bsd")) {
         addName(names, "BrowserOS-NIX");
         addName(names, "BrowserOS-BSD");
         if (ua.contains("netbsd")) {
            addName(names, "BrowserOS-BSD-NetBSD");
         } else if (ua.contains("openbsd")) {
            addName(names, "BrowserOS-BSD-OpenBSD");
         } else if (ua.contains("freebsd")) {
            addName(names, "BrowserOS-BSD-FreeBSD");
         }

      // AIX
      } else if (ua.contains("aix")) {
         addName(names, "BrowserOS-NIX");
         addName(names, "BrowserOS-AIX");

      // IRIX
      } else if (ua.contains("irix")) {
         addName(names, "BrowserOS-NIX");
         addName(names, "BrowserOS-IRIX");

      // HP-UX
      } else if (ua.contains("hp-ux")) {
         addName(names, "BrowserOS-NIX");
         addName(names, "BrowserOS-HPUX");

      // Sun Solaris
      } else if (ua.contains("sunos")) {
         addName(names, "BrowserOS-NIX");
         analyze(ua, names, "BrowserOS-Solaris", "sunos ", 1, false);

      // Sun Solaris
      } else if (ua.contains("beos")) {
         addName(names, "BrowserOS-BeOS");

      // OS/2 (a.k.a. Ecomstation)
      } else if (ua.contains("(os/2")) {
         analyze(ua, names, "BrowserOS-OS2", "warp ", 1, false);
      }
   }

   private static final void detectBrowserEngine(String ua, Set<String> names) {

      // Apple WebKit
      if (ua.contains("applewebkit/")) {
         analyze(ua, names, "BrowserEngine-WebKit", "applewebkit/", 4, false);

      // Mozilla Gecko
      } else if (ua.contains("gecko/")) {
         analyze(ua, names, "BrowserEngine-Gecko", "rv:", 4, false);

      // Opera Presto
      } else if (ua.contains("presto/")) {
         analyze(ua, names, "BrowserEngine-Presto", "presto/", 3, false);
      } else if (ua.contains("presto")) {
         analyze(ua, names, "BrowserEngine-Presto", "presto ", 3, false);

      // Microsoft Trident
      } else if (ua.contains("trident/")) {
         analyze(ua, names, "BrowserEngine-Trident", "trident/", 3, false);
      } else if (ua.contains("trident")) {
         analyze(ua, names, "BrowserEngine-Trident", "trident ", 3, false);

      // KDE KHTML
      } else if (ua.contains("khtml/")) {
         analyze(ua, names, "BrowserEngine-KHTML", "khtml/", 3, false);
      }
   }

   private static final void detectBrowser(String ua, Set<String> names) {

      // Lunascape, can use different rendering engines
      // E.g.: Lunascape5 (Webkit) - Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/528+ (KHTML, like Gecko, Safari/528.0) Lunascape/5.0.3.0
      if (ua.contains("lunascape")) {
         analyze(ua, names, "Browser-Lunascape", "lunascape ", 4, false);
         analyze(ua, names, "Browser-Lunascape", "lunascape/", 4, false);

      // Maxthon
      } else if (ua.contains("maxthon")) {
         analyze(ua, names, "Browser-Maxthon", "maxthon ");

      // Konqueror (needs to be detected before Gecko-based browsers)
      // E.g.: Mozilla/5.0 (compatible; Konqueror/4.1; Linux) KHTML/4.1.2 (like Gecko)
      } else if (ua.contains("konqueror")) {
         analyze(ua, names, "Browser-Konqueror", "konqueror/", 2, false);
         addName(names, "BrowserEngine-KHTML");

      // Fennec
      // E.g.: Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.9.2a1pre) Gecko/20090317 Fennec/1.0b1
      //       Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1b2pre) Gecko/20081015 Fennec/1.0a1
      //       Mozilla/5.0 (X11; U; Linux armv7l; en-US; rv:1.9.2a1pre) Gecko/20090322 Fennec/1.0b2pre
      } else if (ua.contains("fennec")) {
         analyze(ua, names, "Browser-Fennec", "fennec/");

      // Epiphany
      // E.g.: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.3) Gecko/20041007 Epiphany/1.4.7
      } else if (ua.contains("epiphany")) {
         analyze(ua, names, "Browser-Epiphany", "epiphany/");

      // Flock (needs to be detected before Firefox)
      // E.g.: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.18) Gecko/20081107 Firefox/2.0.0.18 Flock/1.2.7
      } else if (ua.contains("flock")) {
         analyze(ua, names, "Browser-Flock", "flock/");

      // Camino (needs to be detected before Firefox)
      // E.g.: Mozilla/5.0 (Macintosh; U; Intel Mac OS X; nl; rv:1.8.1.14) Gecko/20080512 Camino/1.6.1 (MultiLang) (like Firefox/2.0.0.14)
      } else if (ua.contains("camino")) {
         analyze(ua, names, "Browser-Camino", "camino/");

      // SeaMonkey
      // E.g.: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1b3pre) Gecko/20090302 SeaMonkey/2.0b1pre
      } else if (ua.contains("seamonkey/")) {
         analyze(ua, names, "Browser-SeaMonkey", "seamonkey/");

      // SeaMonkey (again)
      // E.g.: Seamonkey-1.1.13-1(X11; U; GNU Fedora fc 10) Gecko/20081112
      } else if (ua.contains("seamonkey-")) {
         analyze(ua, names, "Browser-SeaMonkey", "seamonkey-");
         addName(names, "BrowserEngine-Gecko");

      // Netscape Navigator (needs to be detected before Firefox)
      // E.g.: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.5pre) Gecko/20070712 Firefox/2.0.0.4 Navigator/9.0b2
      } else if (ua.contains("navigator/")) {
         analyze(ua, names, "Browser-Netscape", "navigator/");
         addName(names, "BrowserEngine-Gecko");

      // Firefox
      } else if (ua.contains("firefox")) {
         analyze(ua, names, "Browser-Firefox", "firefox/");
      } else if (ua.contains("minefield/")) {
         analyze(ua, names, "Browser-Firefox", "minefield/");
      } else if (ua.contains("namoroka/")) {
         analyze(ua, names, "Browser-Firefox", "namoroka/"); // Firefox 3.6 pre-releases
      } else if (ua.contains("shiretoko/")) {
         analyze(ua, names, "Browser-Firefox", "shiretoko/"); // Firefox 3.5 pre-releases
      } else if (ua.contains("firebird/")) {
         analyze(ua, names, "Browser-Firefox", "firebird/"); // Before 1.0
      } else if (ua.contains("phoenix/")) {
         analyze(ua, names, "Browser-Firefox", "phoenix/"); // Before 1.0 (and before Firebird code-name)

      // Opera
      } else if (ua.startsWith("opera/")) {

         addName(names, "BrowserEngine-Presto");
         addName(names, "Browser-Opera");

         // Opera Mobile
         if (ua.contains("mobi/")) {
            analyze(ua, names, "Browser-OperaMobile", ua.contains("version/") ? "version/" : "opera/", 3, true);

         // Opera Mini
         } else if (ua.contains("mini/")) {
            analyze(ua, names, "Browser-OperaMini", "mini/", 3, true);

         // Opera Desktop
         } else {
            analyze(ua, names, "Browser-OperaDesktop", ua.contains("version/") ? "version/" : "opera/", 3, true);
         }

      // Opera (older releases)
      } else if (ua.contains("opera")) {
         addName(names, "Browser-Opera");
         analyze(ua, names, "Browser-OperaDesktop", "opera ");
         addName(names, "BrowserEngine-Presto");

      // Palm Pre browser - this one needs to be checked before Safari
      } else if (ua.contains("pre/")) {
         analyze(ua, names, "Browser-PalmPreBrowser", "version/");

      // OmniWeb - this one needs to be checked before Safari
      } else if (ua.contains("omniweb")) {
         addName(names, "Browser-OmniWeb");

      // Google Chrome - this one needs to be checked before Safari
      // e.g.: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.X.Y.Z Safari/525.13.
      } else if (ua.contains("chrome")) {
         analyze(ua, names, "Browser-Chrome", "chrome/", 4, false);

      // Apple Safari
      } else if (ua.contains("safari")) {
         addName(names, "BrowserEngine-WebKit");
         addName(names, "Browser-Safari"      );

         if (ua.contains("mobile/") || ua.contains("android")) {
            analyze(ua, names, "Browser-MobileSafari", "version/");
         } else {
            analyze(ua, names, "Browser-DesktopSafari", "version/");
         }

      // Netscape (again)
      } else if (ua.contains("netscape6")) {
         analyze(ua, names, "Browser-Netscape", "netscape6/");
         addName(names, "Browser-Netscape");
         addName(names, "Browser-Netscape-6");
         addName(names, "BrowserEngine-Gecko");
      } else if (ua.contains("netscape")) {
         analyze(ua, names, "Browser-Netscape", "netscape/", 3, true);
         addName(names, "BrowserEngine-Gecko");

      // iCab
      // E.g.: iCab/4.5 (Macintosh; U; Mac OS X Leopard 10.5.7)
      } else if (ua.contains("icab")) {
         analyze(ua, names, "Browser-iCab", "icab/");
         analyze(ua, names, "Browser-iCab", "icab ");

         // iCab 4 uses the WebKit rendering engine, although the user agent
         // string does not advertise that
         if (names.contains("Browser-iCab-4")) {
            addName(names, "BrowserEngine-WebKit");
         }

      // Internet Explorer
      } else if (ua.contains("msie")) {
         addName(names, "BrowserEngine-Trident");
         addName(names, "Browser-MSIE"         );

         // Mobile IE
         if (ua.contains("iemobile")) {
            analyze(ua, names, "Browser-MobileMSIE", "iemobile ", 3, true);
         } else if (names.contains("BrowserOS-Windows-Mobile")) {
            addName(names, "Browser-MobileMSIE");
         } else {
            analyze(ua, names, "Browser-DesktopMSIE", "msie ", 3, true);
         }

      // Netscape 4
      } else if (! ua.contains("(compatible") && (ua.startsWith("mozilla/4.") || ua.startsWith("mozilla/3."))) {
         analyze(ua, names, "Browser-Netscape", "mozilla/", 3, true);
      }
   }

   private static final void addName(Set<String> names, String newName) {
      if (! names.contains(newName)) {
         names.add(newName);
      }
   }

   private static final void analyze(String ua, Set<String> names, String basicName, String versionPrefix) {
      analyze(ua, names, basicName, versionPrefix, 3, false);
   }

   private static final void analyze(String ua, Set<String> names, String basicName, String versionPrefix, int minVersionParts, boolean splitSecondVersionPart) {

      // Normalize the arguments
      ua            =            ua.toLowerCase();
      versionPrefix = versionPrefix.toLowerCase();

      // First add the basic name
      addName(names, basicName);

      // Find the location of the version number after the prefix
      int index = ua.indexOf(versionPrefix);
      if (index >= 0) {

         // Get the version number in a string
         String version = cutVersionEnd(ua.substring(index + versionPrefix.length()).trim());
         // XXX: System.err.println("User agent \"" + ua + "\": Found version number \"" + version + "\".");

         if (version.length() > 0) {

            // Split the version number in pieces
            String[] versionParts = version.split("\\.");

            // First version part can always be done immediately
            String specificName = basicName + '-' + versionParts[0];
            addName(names, specificName);

            int versionPartsFound;
            if (splitSecondVersionPart && versionParts.length == 2) {
               versionPartsFound = 1;

               String secondVersionPart = versionParts[1];
               for (int i = 0; i < secondVersionPart.length(); i++) {
                  specificName += "-" + secondVersionPart.charAt(i);
                  addName(names, specificName);
                  versionPartsFound++;
               }
            } else {
               for (int i = 1; i < versionParts.length; i++) {
                  specificName += '-' + versionParts[i];
                  addName(names, specificName);
               }
               versionPartsFound = versionParts.length;
            }

            for (int i = versionPartsFound; i < minVersionParts; i++) {
               specificName += "-0";
               addName(names, specificName);
            }
         }
      }
   }

   private static final String cutVersionEnd(String s) {
      String result = "";
      for (int i = 0; i < s.length(); i++) {
         char c = s.charAt(i);
         if (Character.isDigit(c) || c == '.') {
            result += c;
         } else {
            break;
         }
      }

      return result;
   }


   //-------------------------------------------------------------------------
   // Class fields
   //-------------------------------------------------------------------------

   private static final String[] UA_MOBILE_DEVICE_SNIPPETS = new String[] {
      "windows ce", "windowsce", "symbian", "nokia", "opera mini", "wget", "fennec", "opera mobi", "windows; ppc", "blackberry"
   };

   private static final String[] UA_MOBILE_DEVICE_WITHOUT_TEL_SUPPORT = new String[] {
      "opera/8.", "opera/7.", "opera/6.", "opera/5.", "opera/4.", "opera/3.", "ipod"
   };

   private static final String[] UA_BOT_SNIPPETS = new String[] {
      "spider", "bot", "crawl", "miner", "checker", "java", "pingdom"
   };


   //-------------------------------------------------------------------------
   // Constructors
   //-------------------------------------------------------------------------

   /**
    * Constructs a new <code>UserAgentSniffer</code> instance.
    */
   private UserAgentSniffer() {
      // empty
   }
}
