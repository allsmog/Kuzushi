import process from "node:process";

export async function writeBridgeResponseAndExit(response, exitCode) {
  await writeBridgePayload(JSON.stringify(response));
  process.exit(exitCode);
}

export async function writeBridgePayload(payload) {
  await new Promise((resolve, reject) => {
    process.stdout.write(payload, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
