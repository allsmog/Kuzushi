/**
 * Language profile registry — maps language names to profiles.
 */

import { cCppProfile } from "./c-cpp.js";
import { goProfile } from "./go.js";
import { javaKotlinProfile } from "./java-kotlin.js";
import { jstsProfile } from "./javascript-typescript.js";
import { phpProfile } from "./php.js";
import { pythonProfile } from "./python.js";
import { rubyProfile } from "./ruby.js";
import { rustProfile } from "./rust.js";
import type { LanguageProfile } from "./types.js";

const PROFILES: LanguageProfile[] = [
  cCppProfile,
  javaKotlinProfile,
  pythonProfile,
  goProfile,
  jstsProfile,
  rustProfile,
  phpProfile,
  rubyProfile,
];

const BY_ID = new Map<string, LanguageProfile>();
for (const profile of PROFILES) {
  BY_ID.set(profile.languageId.toLowerCase(), profile);
  for (const alias of profile.aliases) {
    BY_ID.set(alias.toLowerCase(), profile);
  }
}

export function getLanguageProfile(language: string): LanguageProfile | undefined {
  return BY_ID.get(language.toLowerCase());
}

export function getLanguageProfiles(languages: string[]): LanguageProfile[] {
  const seen = new Set<string>();
  const result: LanguageProfile[] = [];
  for (const lang of languages) {
    const profile = BY_ID.get(lang.toLowerCase());
    if (profile && !seen.has(profile.languageId)) {
      seen.add(profile.languageId);
      result.push(profile);
    }
  }
  return result;
}
