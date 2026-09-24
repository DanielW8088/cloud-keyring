const ALGORITHMS: Record<string, string> = {
  "ssh-ed25519": "ED25519",
  "ssh-rsa": "RSA",
  "ecdsa-sha2-nistp256": "ECDSA P-256",
  "ecdsa-sha2-nistp384": "ECDSA P-384",
  "ecdsa-sha2-nistp521": "ECDSA P-521",
  "sk-ssh-ed25519@openssh.com": "ED25519 security key",
  "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA security key",
};

export interface ParsedPublicKey {
  line: string;
  type: string;
  typeLabel: string;
  blob: string;
  comment: string;
  fingerprint: string;
}

class BlobReader {
  private offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  field(): Uint8Array {
    if (this.offset + 4 > this.bytes.length) throw new Error("Truncated SSH key blob");
    const view = new DataView(this.bytes.buffer, this.bytes.byteOffset + this.offset, 4);
    const length = view.getUint32(0);
    this.offset += 4;
    if (length > 16_384 || this.offset + length > this.bytes.length) {
      throw new Error("Invalid SSH key field length");
    }
    const value = this.bytes.slice(this.offset, this.offset + length);
    this.offset += length;
    return value;
  }

  text(): string {
    return new TextDecoder("utf-8", { fatal: true }).decode(this.field());
  }

  done(): boolean {
    return this.offset === this.bytes.length;
  }
}

function decodeBase64(value: string): Uint8Array {
  if (value.length === 0 || value.length > 24_000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) {
    throw new Error("Invalid SSH public key encoding");
  }
  const unpadded = value.replace(/=+$/, "");
  if (unpadded.includes("=") || unpadded.length % 4 === 1) throw new Error("Invalid SSH public key encoding");
  const padded = unpadded.padEnd(Math.ceil(unpadded.length / 4) * 4, "=");
  if (value.includes("=") && value !== padded) throw new Error("Invalid SSH public key encoding");
  try {
    const decoded = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
    if (base64(decoded).replace(/=+$/, "") !== unpadded) {
      throw new Error("Invalid SSH public key encoding");
    }
    return decoded;
  } catch {
    throw new Error("Invalid SSH public key encoding");
  }
}

function significantBits(value: Uint8Array): number {
  let first = 0;
  while (first < value.length && value[first] === 0) first++;
  if (first === value.length) return 0;
  const byte = value[first] ?? 0;
  return (value.length - first - 1) * 8 + (32 - Math.clz32(byte));
}

function validateBlob(type: string, bytes: Uint8Array): void {
  const reader = new BlobReader(bytes);
  if (reader.text() !== type) throw new Error("SSH key type does not match its encoded blob");

  if (type === "ssh-ed25519") {
    if (reader.field().length !== 32) throw new Error("Invalid ED25519 public key length");
  } else if (type === "ssh-rsa") {
    const exponent = reader.field();
    const modulus = reader.field();
    if (exponent.length === 0 || significantBits(modulus) < 2048) {
      throw new Error("RSA public keys must be at least 2048 bits");
    }
  } else if (type.startsWith("ecdsa-sha2-")) {
    const curve = reader.text();
    const expectedCurve = type.slice("ecdsa-sha2-".length);
    const expectedLengths: Record<string, number> = { nistp256: 65, nistp384: 97, nistp521: 133 };
    const point = reader.field();
    if (curve !== expectedCurve || point[0] !== 4 || point.length !== expectedLengths[curve]) {
      throw new Error("Invalid ECDSA public key encoding");
    }
  } else if (type === "sk-ssh-ed25519@openssh.com") {
    if (reader.field().length !== 32 || reader.field().length === 0) {
      throw new Error("Invalid ED25519 security key encoding");
    }
  } else if (type === "sk-ecdsa-sha2-nistp256@openssh.com") {
    if (reader.text() !== "nistp256") throw new Error("Invalid ECDSA security key curve");
    const point = reader.field();
    if (point.length !== 65 || point[0] !== 4 || reader.field().length === 0) {
      throw new Error("Invalid ECDSA security key encoding");
    }
  } else {
    throw new Error("Unsupported SSH key type");
  }

  if (!reader.done()) throw new Error("Unexpected data in SSH public key blob");
}

function base64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export async function parsePublicKey(input: string): Promise<ParsedPublicKey> {
  if (input.length > 16_384 || /[\x00-\x1f\x7f]/.test(input)) {
    throw new Error("Enter exactly one SSH public key line");
  }
  const parts = input.trim().split(/[\t ]+/);
  const type = parts[0] ?? "";
  const blob = parts[1] ?? "";
  if (!Object.hasOwn(ALGORITHMS, type) || !blob) {
    throw new Error("Use a supported OpenSSH public key without authorized_keys options");
  }
  const comment = parts.slice(2).join(" ");
  if (comment.length > 256) throw new Error("Key comments must not exceed 256 characters");

  const bytes = decodeBase64(blob);
  validateBlob(type, bytes);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes.slice().buffer));
  const fingerprint = `SHA256:${base64(digest).replace(/=+$/, "")}`;
  return {
    line: [type, blob, comment].filter(Boolean).join(" "),
    type,
    typeLabel: keyTypeLabel(type),
    blob,
    comment,
    fingerprint,
  };
}

export function keyTypeLabel(type: string): string {
  return Object.hasOwn(ALGORITHMS, type) ? (ALGORITHMS[type] ?? type) : type;
}
