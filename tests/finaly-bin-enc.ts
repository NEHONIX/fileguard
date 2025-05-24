import path from "path";
import { decryptData, encryptData } from "../src/utils/cryptUtils";
import {
  FortifyJS,
  KeyDerivationAlgorithm,
  Keys,
  Random,
  SecureRandom,
  Validators,
} from "fortify2-js";
import * as crypto from "crypto";

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

// encrypt data
// async function runTest() {
//   const OUTPUT_DIR = path.join(__dirname, "output", "finaly-bin-enc");
//   const binaryFilePath = path.join(OUTPUT_DIR, "finaly-bin-enc.nxs");

//   const result = await encryptData(data, binaryFilePath, {
//     useBinaryFormat: true,
//     securityLevel: "high",
//     compressionLevel: "medium",
//     layers: 2,
//     useAlgorithmRotation: false,
//     addHoneypots: true,
//   });

//   console.log("Binary format encryption successful!");
//   console.log("Encrypt result: ", result);
//   console.log(`File saved to: ${result.filePath}`);
//   console.log(`Original size: ${result.originalSize} bytes`);
// }

console.log({
  x: Random.getRandomBytes(16).toString("hex"),
  y: crypto.randomBytes(16).toString("hex"),
});
