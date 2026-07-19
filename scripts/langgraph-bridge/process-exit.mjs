import process from "node:process";

export async function writeBridgeResponseAndExit(response, exitCode) {
  const payload = JSON.stringify(response);
  await new Promise((resolve, reject) => {
    process.stdout.write(payload, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
  process.exit(exitCode);
}
