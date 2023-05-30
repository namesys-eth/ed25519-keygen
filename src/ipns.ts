import { ed25519 } from '@noble/curves/ed25519';
import { hex, base32 } from '@scure/base';
import { concatBytes } from 'micro-packed';

// Formats IPNS public key in bytes array format to 'ipns://k...' string format
export function formatPublicKey(pubBytes: Uint8Array) {
  // Convert bytes array → hex string → BigInt → base-36 string → IPNS
  return `ipns://k${BigInt(`0x${hex.encode(pubBytes)}`).toString(36)}`;
}

// Takes an IPNS pubkey (address) string as input and returns bytes array of the key
// Supports various formats ('ipns://k', 'ipns://b', 'ipns://f')
// Handles decoding and validation of the key before returning pubkey bytes
export function parseAddress(address: string): Uint8Array {
  if (address.startsWith('ipns://')) address = address.slice(7);
  address = address.toLowerCase();
  let hexKey;
  if (address.startsWith('k')) {
    const b36 = '0123456789abcdefghijklmnopqrstuvwxyz';
    let result = 0n;
    // Iterate over chars in pubkey and convert to BigInt
    for (let i = 1; i < address.length; ) {
      // start at second char
      result = result * 36n + BigInt(b36.indexOf(address.charAt(i++)));
    }
    // Convert BigInt to hex format and pad it with zeros up to length 80
    hexKey = result.toString(16).padStart(80, '0');
  } else if (address.startsWith('b')) {
    // Decode base-32 pubkey (after removing 'b' prefix) and encode it as a hex string
    hexKey = hex.encode(base32.decode(address.slice(1).toUpperCase()));
  } else if (address.startsWith('f')) {
    hexKey = address.slice(1);
  } else throw new Error('Unsupported Base-X Format'); // Throw error if pubkey format is not supported

  // Check if hexKey has expected prefix '0172002408011220' and length of 80
  if (hexKey.startsWith('0172002408011220') && hexKey.length === 80) {
    return hex.decode(hexKey);
  }
  // Throw error if IPNS key prefix is invalid
  throw new Error('Invalid IPNS Key Prefix: ' + hexKey);
}

// Generates an ed25519 pubkey from a seed and converts it to several IPNS pubkey formats
export async function getKeys(seed: Uint8Array) {
  //? privKey "seed" should be checked for <ed25519.curve.n?
  if (seed.length != 32) throw new TypeError('Seed must be 32 bytes in length');
  // Generate ed25519 public key from seed
  const pubKey = await ed25519.getPublicKey(seed);
  // Create public key bytes by concatenating prefix bytes and pubKey
  const pubKeyBytes = concatBytes(
    new Uint8Array([0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20]),
    pubKey
  );
  const hexKey = hex.encode(pubKeyBytes).toLowerCase();
  // Return different representations of the keys
  return {
    publicKey: `0x${hexKey}`,
    privateKey: `0x${hex.encode(
      concatBytes(new Uint8Array([0x08, 0x01, 0x12, 0x40]), seed, pubKey)
    )}`,
    base36: `ipns://k${BigInt(`0x${hexKey}`).toString(36)}`,
    base32: `ipns://b${base32.encode(pubKeyBytes).toLowerCase()}`,
    base16: `ipns://f${hexKey}`,
    contenthash: `0xe501${hexKey}`,
  };
}

export default getKeys;
