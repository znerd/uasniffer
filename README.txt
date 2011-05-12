This is 'uasniffer', a Java library for user agent sniffing. It analyzes a
User-Agent header (typically sent in an HTTP request) and describes what kind
of user agent this header indicates.

The main class is the 'Sniffer' class in the org.znerd.uasniffer package.

This utility library has no runtime dependencies other than the Java
runtime environment, version 1.5 or higher.

This software requires the following to build (with 'mvn package'):

   - Java 1.5 or higher
   - Maven 3.0.2 or higher

This software is available under the terms of a BSD-style license, see
the accompanied LICENSE file.

If you want to file a bug report or a feature request, please do so here:

   http://github.com/znerd/uasniffer/issues

Here's a small code snippet that will analyze your agent string:

   public service(HttpServletRequest req, HttpServletResponse res)
   throws ServletException {
      String agentString = req.getHeader("user-agent");
      UserAgent       ua = Sniffer.analyze(agentString);
      res.getWriter().write("<HTML class=\"" + ua.getNamesAsString() + "\"><BODY>Hello world</BODY></HTML>");
   }
