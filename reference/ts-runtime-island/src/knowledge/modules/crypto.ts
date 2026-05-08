import type { KnowledgeModule } from "../types.js";

export const cryptoModule: KnowledgeModule = {
  id: "crypto-misuse",
  cwes: ["CWE-327", "CWE-328", "CWE-330", "CWE-798", "CWE-295", "CWE-916"],
  languages: [],
  frameworks: [],
  dangerousPatterns: [
    {
      pattern: "MD5/SHA1 for password hashing",
      why: "Fast hashes enable brute-force attacks",
      severity: "ERROR",
    },
    {
      pattern: "ECB mode encryption",
      why: "ECB preserves plaintext patterns in ciphertext",
      severity: "ERROR",
    },
    {
      pattern: "DES/RC4/Blowfish usage",
      why: "Deprecated ciphers with known weaknesses",
      severity: "ERROR",
    },
    {
      pattern: "Math.random() for security tokens",
      why: "Predictable PRNG, not cryptographically secure",
      severity: "ERROR",
    },
    {
      pattern: "Hardcoded keys/secrets in source",
      why: "Keys in code are extractable from builds/repos",
      severity: "ERROR",
    },
    {
      pattern: "TLS certificate verification disabled",
      why: "Enables MITM attacks",
      severity: "ERROR",
    },
    {
      pattern: "TLS version < 1.2",
      why: "Older TLS versions have known vulnerabilities",
      severity: "WARNING",
    },
    {
      pattern: "Unsalted password hashing",
      why: "Rainbow table attacks become feasible",
      severity: "ERROR",
    },
  ],
  safePatterns: [
    {
      pattern: "bcrypt/scrypt/Argon2 for passwords",
      why: "Purpose-built password hashing with work factors",
    },
    { pattern: "AES-GCM or ChaCha20-Poly1305", why: "Modern authenticated encryption" },
    { pattern: "crypto.randomBytes() / os.urandom()", why: "Cryptographically secure random" },
    {
      pattern: "TLS 1.3 with proper CA validation",
      why: "Current best practice for transport security",
    },
  ],
  bypassTechniques: [
    "Weak key derivation allows brute-force of derived keys",
    "ECB mode enables block-level manipulation of ciphertext",
    "Predictable IVs/nonces enable known-plaintext attacks",
    "Timing side-channels in comparison operations",
    "Key reuse across different contexts",
  ],
  detectionKeywords: [
    "crypto",
    "hashlib",
    "javax.crypto",
    "bcrypt",
    "argon2",
    "scrypt",
    "md5",
    "sha1",
    "sha256",
    "aes",
    "des",
    "rc4",
    "randomBytes",
    "Math.random",
    "createCipher",
    "createHash",
  ],
  fixExamples: [
    {
      language: "JavaScript",
      before: "crypto.createHash('md5').update(password).digest('hex')",
      after: "await bcrypt.hash(password, 12)",
      explanation: "Use bcrypt with appropriate work factor for password storage",
    },
  ],
  tags: ["crypto", "encryption", "hashing", "passwords", "keys"],
};
