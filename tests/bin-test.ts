import path from "path";
import { decryptData, encryptData } from "../src/utils/cryptUtils";

const res = {
  filePath:
    "F:\\Projects\\NEHONIX\\NHX File\\tests\\output\\bin-test\\bin-test.nxs",
  originalSize: 29,
  encryptedSize: 1755,
  compressionRatio: 0.016524216524216526,
  encryptionKeyHex:
    "585c7595473535a6dbcc9d47d12cc05770dff4d07c108aa8f6ad9c8c84fb5a2d",
  rsaKeyPair: {
    publicKey:
      "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAustigfmXGTJ7dkwwjkvl\ncHDnveUJJMdNflTPrka6LMYR37AniTcRYzBuIlPOdeONB95zG8LpOqn3WlmEWzyH\nB/tBctA2zxY30bL/DLJWIHeSQhzLFjxDKHxA1t81V+LDJ8+CSFziZFo8L0lJk4A5\ncCFRBbOk9LQ/wu/vyme/9zTqW1GP2/Kyp4kfYmjwy3PAGotdqYMkD56fWBLcnxWA\nxWPQdV41B6zV9/dvEHeyhbMsufK3A6Ef4Dh9cBADnkNtUQphi7hO7TuOE1ryDtQ8\nMKory+Ozgbq3wy4SdR1Ehoxcnu4rVqLiQyr40N6f4BsqF/kPgjIdyJ2OYU+mi1s1\nrwIDAQAB\n-----END PUBLIC KEY-----\n",
    privateKey:
      "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6y2KB+ZcZMnt2\nTDCOS+VwcOe95Qkkx01+VM+uRrosxhHfsCeJNxFjMG4iU851440H3nMbwuk6qfda\nWYRbPIcH+0Fy0DbPFjfRsv8MslYgd5JCHMsWPEMofEDW3zVX4sMnz4JIXOJkWjwv\nSUmTgDlwIVEFs6T0tD/C7+/KZ7/3NOpbUY/b8rKniR9iaPDLc8Aai12pgyQPnp9Y\nEtyfFYDFY9B1XjUHrNX3928Qd7KFsyy58rcDoR/gOH1wEAOeQ21RCmGLuE7tO44T\nWvIO1DwwqivL47OBurfDLhJ1HUSGjFye7itWouJDKvjQ3p/gGyoX+Q+CMh3InY5h\nT6aLWzWvAgMBAAECggEAFepQx2EKGjmzBIER3VAIPjXw6nWZqgf8DotSxmaj5ybh\n5/WZ3d5pGtMOyNY+TdSBsl+l76bhiDFyxNXl0nJ6gTQ4TIkjNQ6tQ9wVUl8F/c8p\niLoqFZTCaFiTnuIXNxVywhP1fBnxscZocz/M8xJDKuWtxNZ7zv3q0SsnXf7oJc+L\nJt2hsaY1u8cdB8Gi4AmZH8OI4t9Q+nUAPxg/9gLtCN3Ah4q4jacdq6j//IH/WK76\nbeLV8WhqDbSktjlNH+3dHCsU/njQSBEDvKjLMpWm3uT33PStrGp4HR4wXZCbE+Sn\nTxaGIvlCAprPKH3IrblbVW1uPEhzBohKyDKfcvHqWQKBgQDkdESqPpV5qwk5i8lZ\nR4TIuHvReJdrLk+L0f66+HIpBVsZm270K5shrpo7qkAUOJNOu+dZqCP7e2TknQy8\njbh8dhTE7Ds0ZGP5NL8yjb4T+maxqTM9fBVx3mhKz4Xqs58Lf+IHIpqSFl1rrPws\nTVmsYNI1tq6nBFV/JREnQwVfGwKBgQDRUTMqsOk+6cKPNf1LWU0M+qBsP5BEhiZV\negJzR6c0EMek3NKmfqgEbvbdpkasGII2/honLe4pN7CGLxI3E1+GFFGyz9aj6S+e\nRPiCw0fZr49lbdEJA2j+H/W1JLW6KTweKAJYbOtZAKkinyReWQ47iJSzLt/P5W6a\nlsqLe5Ao/QKBgBWb5c7QoqTih7nYvg/i0u2Ffbi/llr+A2ovT8/xpiK5LffLGwCf\ni0nxUQdpwCvpeg2NeoGhhN3Juy5gqI7BPP0Q0kAaNDNtd4Nf+OHYRG1xVvthDMa5\nEPI3XlgNLxaXLOkSjJeuLz64PNftgeDS5DOI6PlJsVV89HVVVT0Iet6XAoGANxGf\n3olwtAaYE0lm/F3gMZv2fMQ0VnLcvvw8jMu7J62KeMtH+Fm2JoRzGllWmoxQJduw\nUcJ5uApYvNTBfA/yv7m0zNB1beY5ivAmWXC7BIB1v3+m0TI+ey05XZDs5q9Wi7CG\n/XCacm4EEYHA9bmETxFd3c5lP7Li6HTnkM7PXJkCgYBf9mhn199XHFaRSPGubqsU\n0JDFEkC0TuszGlOSOzx9uMfaroJ4fjfW8gRQK7RjTLKKjFZuYg83j2w6pz9uhCiS\njlx9hl4U0Ke9KC9dgrJ3+dVkaS4BoHQK/KKIie6IjM0CZmg7frMBBWwzHzxLFsBU\nvqbYz7gYsCp2Anc8IB7eCw==\n-----END PRIVATE KEY-----\n",
  },
  usedBinaryFormat: true,
  usedUltraSecure: false,
};

async function runTest() {
  //   const data = [{ user: "test3" }, "p1", 2, 0x204];
  //   const OUTPUT_DIR = path.join(__dirname, "output", "bin-test");
  //   const binaryFilePath = path.join(OUTPUT_DIR, "bin-test.nxs");

  const binaryResult = await decryptData(
    res.filePath,
    res.encryptionKeyHex,
    res.rsaKeyPair,
    false,
    true
  );
  //   const binaryResult = await encryptData(data, binaryFilePath, {
  //     useBinaryFormat: true,
  //     securityLevel: "high",
  //     compressionLevel: "medium",
  //     layers: 2,
  //   });

  console.log("Binary format encryption successful!");
  console.log("Encrypt result: ", binaryResult);
  console.log(`File saved to: ${binaryResult.filePath}`);
  console.log(`Original size: ${binaryResult.originalSize} bytes`);
  console.log(`Encrypted size: ${binaryResult.encryptedSize} bytes`);
}
runTest();
