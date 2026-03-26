import type { KnowledgeModule } from "../types.js";

export const fileUploadModule: KnowledgeModule = {
  id: "file-upload",
  cwes: ["CWE-434"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    { pattern: "File upload without extension/MIME validation", why: "Allows upload of executable files (PHP, JSP, ASPX)", severity: "ERROR" },
    { pattern: "File saved to web-accessible directory with original name", why: "Uploaded shells become directly accessible", severity: "ERROR" },
    { pattern: "Content-Type from request used without server-side validation", why: "Client controls Content-Type header, can be spoofed", severity: "WARNING" },
    { pattern: "File path constructed from user-supplied filename", why: "Path traversal via ../../../etc/passwd in filename", severity: "ERROR" },
    { pattern: "Image processing without size/dimension limits", why: "Pixel flood DoS or ImageTragick-style RCE", severity: "WARNING" },
  ],
  safePatterns: [
    { pattern: "Server-generated UUID filename", why: "User cannot control destination path" },
    { pattern: "Extension allowlist (not blocklist)", why: "Only known-safe extensions accepted" },
    { pattern: "File stored outside web root", why: "Cannot be directly accessed via HTTP" },
    { pattern: "Magic byte validation", why: "Verifies actual file type, not just extension/MIME" },
    { pattern: "File served via signed URL or proxy", why: "No direct filesystem access from web" },
  ],
  bypassTechniques: [
    "Double extension (file.php.jpg) bypassing extension checks",
    "Null byte injection (file.php%00.jpg) in legacy systems",
    "MIME type spoofing (Content-Type: image/jpeg for PHP file)",
    "Case variation (.PhP, .pHp) on case-insensitive filesystems",
    ".htaccess upload to reconfigure Apache handler mapping",
    "SVG with embedded JavaScript (XSS via image upload)",
    "Polyglot files (valid image AND valid PHP/script)",
  ],
  detectionKeywords: [
    "multer", "formidable", "busboy", "express-fileupload",
    "FileUpload", "multipart", "move_uploaded_file",
    "saveAs", "writeFile", "createWriteStream",
    "Content-Disposition", "originalname", "filename",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "fs.writeFileSync(`uploads/${req.file.originalname}`, req.file.buffer)",
      after: "const ext = path.extname(req.file.originalname).toLowerCase(); if (!ALLOWED_EXTS.has(ext)) throw new Error('blocked'); fs.writeFileSync(`uploads/${uuid()}${ext}`, req.file.buffer)",
      explanation: "Use UUID filename, validate extension against allowlist, store outside web root",
    },
  ],
  tags: ["upload", "file", "rce"],
};
