import { FortifyJS as fty } from "fortify2-js";
import * as crypto from "crypto";
const ftyBuffer = fty.deriveKey("password", {
  algorithm: "pbkdf2",
  iterations: 100000,
  salt: fty.generateSecureToken({ length: 16, entropy: "maximum" }),
  keyLength: 32,
});
const cryptoBuffer = crypto.randomBytes(1024);
console.log("ftyBuffer: ", ftyBuffer);
// console.log("cryptoBuffer: ", cryptoBuffer);
