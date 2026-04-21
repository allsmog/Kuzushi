/** External reference on a module/tool/finding — CVE, CWE, URL, ATT&CK, etc. */
export interface ModuleReference {
  type: "CVE" | "CWE" | "URL" | "ATT&CK" | "OSVDB" | "BID" | "EDB" | "KB" | "OWASP";
  value: string;
}
