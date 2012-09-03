This is 'uasniffer', a Java library for user agent sniffing. It analyzes a
User-Agent header (typically sent in an HTTP request) and describes what kind
of user agent this header indicates.

Among other, the following are detected:
- common browsers: MSIE, Firefox, Safari, Chrome, Opera, etc.
- e-readers, e.g. including the Nook, Kindle, Kindle Fire, etc.
- all iOS devices (iPod Touch, iPhone, iPad)
- Microsoft Windows (3.1, 95, 98, ME, 2000, XP, 7, 8, etc.)
- MacOS (up until Mountain Lion)
- Linux, including Android variants
- less common OSes: AIX, FreeBSD, HPUX, IRIX, BeOS, etc.
- Firefox (from early Phoenix prototypes up until 15+)
- Blackberry devices
- Symbian devices (e.g. Nokia and Samsung phones)
- Sony PlayStation (PSP) devices, including the Vita
- less common browsers: Epiphany, Maxthon, Flock, Camino, Konqueror,
  OmniWeb, Dolphin, etc.
- old browsers: NCSA Mosaic, Netscape 1+, MSIE 2+, etc.
- mobile and mini variants, e.g. Opera Mini, Fennec, IE Mobile, etc.
- bots, such as Pingdom and the Google Bot

The quality of this library is maintained by an extensive set of unit
tests, for 300+ user agent strings.

This utility library has no runtime dependencies other than the Java
runtime environment, version 1.5 or higher.

This software requires the following to build (with 'mvn package'):

   - Java 1.5 or higher
   - Maven 3.0.2 or higher

The main class is the 'Sniffer' class in the org.znerd.uasniffer package.

This software is available under the terms of a BSD-style license, see
the accompanied LICENSE file.

If you want to file a bug report or a feature request, please do so here:

   http://github.com/znerd/uasniffer/issues

Here's a small code snippet that will analyze your agent string and put
some relevant CSS class names in your <HTML> tag:

   public service(HttpServletRequest req, HttpServletResponse res)
   throws ServletException {
      String agentString = req.getHeader("user-agent");
      UserAgent       ua = Sniffer.analyze(agentString);
      res.getWriter().write("<HTML class=\"" + ua.getNamesAsString() + "\"><BODY>Hello world</BODY></HTML>");
   }
