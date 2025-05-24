import path from "path";
import { decryptData, encryptData } from "../src/utils/cryptUtils";

const data = {
  users: [
    {
      username: "admin",
      password: "admin",
      role: "admin",
    },
    {
      username: "user",
      password: "user",
      role: "user",
    },
    {
      username: "guest",
      password: "guest",
      role: "guest",
    },
  ],
  usersDashboard: [
    {
      title: "User Dashboard",
      content: "Welcome to the user dashboard!",
      access: "user",
    },
    {
      title: "Guest Dashboard",
      content: "Welcome to the guest dashboard!",
      access: "guest",
    },
    {
      title: "Admin Dashboard",
      content: "Welcome to the admin dashboard!",
      access: "admin",
    },
  ],
};

async function runTest() {
  const OUTPUT_DIR = path.join(__dirname, "output", "finaly-bin-enc");
  const binaryFilePath = path.join(OUTPUT_DIR, "finaly-bin-enc.nxs");

  const binaryResult = await encryptData(data, binaryFilePath, {
    useBinaryFormat: true,
    securityLevel: "high",
    compressionLevel: "maximum",
    layers: 7,
    useAlgorithmRotation: true,
    addHoneypots: true,
    useSmartRSAKeySize: true,
  });

  console.log("Binary format encryption successful!");
  console.log("Encrypt result: ", binaryResult);
  console.log(`File saved to: ${binaryResult.filePath}`);
  console.log(`Original size: ${binaryResult.originalSize} bytes`);
  console.log(`Encrypted size: ${binaryResult.encryptedSize} bytes`);
  console.log(`Compression ratio: ${binaryResult.compressionRatio}`);
  console.log(`RSA key size used: ${binaryResult.rsaKeySize} bits`);

  // decoding
  const decryptedData = await decryptData(
    binaryResult.filePath,
    binaryResult.encryptionKeyHex,
    binaryResult.rsaKeyPair!,
    false,
    true
  );

  console.log("Decrypted data: ", decryptedData);
}

runTest();
