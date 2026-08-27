import path from "node:path";
import { pathToFileURL } from "node:url";
import { nativePlatformPackage, nativePlatformPackages } from "./native-runtime-contract.mjs";

export function selectLocalTarballs(manifest, directory, slug, platform, arch) {
  const selectedPlatform = nativePlatformPackages.find((candidate) => candidate.slug === slug);
  if (!selectedPlatform) throw new Error(`unknown release platform ${slug}`);
  const hostPlatform = nativePlatformPackage(platform, arch);
  if (hostPlatform?.slug !== slug) {
    throw new Error(`release smoke ${slug} cannot run on ${platform}-${arch}`);
  }
  const root = manifest.files.find((record) => record.kind === "root-npm");
  const native = manifest.files.find(
    (record) => record.kind === "platform-npm" && record.slug === slug,
  );
  if (!root || !native) throw new Error(`release manifest is missing local tarballs for ${slug}`);
  return {
    root,
    native,
    rootPath: path.join(directory, root.file),
    nativePath: path.join(directory, native.file),
  };
}

export function localConsumerManifest(version, selected) {
  return {
    name: "kuzushi-local-release-smoke",
    version: "0.0.0",
    private: true,
    dependencies: {
      kuzushi: pathToFileURL(selected.rootPath).href,
      [selected.native.name]: pathToFileURL(selected.nativePath).href,
    },
    kuzushiExpectedVersion: version,
  };
}
