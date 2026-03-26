import type { KnowledgeModule } from "../types.js";

export const xxeModule: KnowledgeModule = {
  id: "xxe",
  cwes: ["CWE-611", "CWE-776"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    { pattern: "XML parser processing user-controlled input with external entities enabled", why: "Allows file read, SSRF, and DoS via entity expansion", severity: "ERROR" },
    { pattern: "DocumentBuilderFactory without DISALLOW_DOCTYPE_DECL", why: "Java XML parser allows DTD processing by default", severity: "ERROR" },
    { pattern: "lxml.etree.parse() with default settings", why: "lxml enables external entity resolution by default", severity: "ERROR" },
    { pattern: "LIBXML_NOENT flag in PHP XML parsing", why: "Explicitly enables entity substitution", severity: "ERROR" },
    { pattern: "XmlDocument.LoadXml() without XmlResolver=null", why: ".NET XML defaults allow external entities", severity: "WARNING" },
  ],
  safePatterns: [
    { pattern: "defusedxml library usage", why: "Disables all dangerous XML features by default" },
    { pattern: "FEATURE_SECURE_PROCESSING enabled", why: "Java secure processing restricts entity expansion" },
    { pattern: "DISALLOW_DOCTYPE_DECL set to true", why: "Prevents DOCTYPE declarations entirely" },
    { pattern: "XmlResolver set to null", why: ".NET: prevents external entity resolution" },
    { pattern: "xml2js default configuration", why: "Node.js xml2js does not process entities by default" },
  ],
  bypassTechniques: [
    "Parameter entities (%entity;) when general entities are disabled",
    "DTD fetching for SSRF even without entity expansion",
    "UTF-7/UTF-16 encoding to bypass WAF entity detection",
    "XInclude as alternative to external entities",
    "SVG files with embedded XML entities (image upload vectors)",
    "XSLT injection when XSLT processing is enabled alongside XML parsing",
  ],
  detectionKeywords: [
    "DocumentBuilderFactory", "SAXParserFactory", "XMLInputFactory",
    "etree.parse", "lxml", "xml.sax", "minidom",
    "xml2js", "fast-xml-parser", "libxmljs",
    "DOMDocument", "simplexml_load", "XmlDocument",
    "LIBXML_NOENT",
  ],
  fixExamples: [
    {
      language: "Java",
      before: "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.newDocumentBuilder().parse(input)",
      after: "DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true); dbf.newDocumentBuilder().parse(input)",
      explanation: "Disable DOCTYPE declarations to prevent all XXE attacks",
    },
  ],
  tags: ["xxe", "xml", "injection"],
};
