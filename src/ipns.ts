import { ed25519 } from '@noble/curves/ed25519';
import { hex, base32 } from '@scure/base';
import { concatBytes } from 'micro-packed';

const ADDRESS_VERSION = new Uint8Array([0x03]);
//const NAMESPACE = new Uint8Array([0xe5]);

// Formats IPNS public key in bytes array format to 'ipns://k...' string format
export function formatPublicKey(pubBytes: Uint8Array) {
  // Convert bytes array to hex string
  const hexString = hex.encode(pubBytes);
  // Convert hex string to BigInt
  const pubBigInt = BigInt(`0x${hexString}`);
  // Convert BigInt to base-36 string
  const base36String = pubBigInt.toString(36);
  // Return public key string in format: 'ipns://k' + base36String
  return `ipns://k${base36String}`;
}

// Takes an IPNS pubkey (address) string as input and returns bytes array of the key
// Supports various formats ('ipns://k', 'ipns://b', 'ipns://f')
// Handles decoding and validation of the key before returning pubkey bytes
export function parseAddress(address: string): Uint8Array {
  // Verify if pubkey starts with 'ipns://' and remove 'ipns://' prefix
  if (address.startsWith('ipns://')) address = address.slice(7);
  // Convert pubkey to lowercase
  address = address.toLowerCase();
  let hexKey;
  if (address.startsWith('k')) {
    const b36 = '0123456789abcdefghijklmnopqrstuvwxyz';
    let result = 0n;
    // Iterate over chars in pubkey, starting from the second char
    for (let i = 1; i < address.length; ) {
      // Convert each base-36 char to BigInt
      result = result * 36n + BigInt(b36.indexOf(address.charAt(i++)));
    }
    // Convert BigInt to hex format and pad it with zeros up to length 80
    hexKey = result.toString(16).padStart(80, '0');
  } else if (address.startsWith('b')) {
    // Decode base-32 pubkey (after removing 'b' prefix) and encode it as a hex string
    hexKey = hex.encode(base32.decode(address.slice(1).toUpperCase()));
  } else if (address.startsWith('f')) {
    // Remove 'f' prefix from pubkey
    hexKey = address.slice(1);
  } else throw new Error('Unsupported Base-X Format'); // Throw an error if the pubkey format is not supported

  // Check if the hexKey has the expected prefix '0172002408011220' and a length of 80 characters
  if (hexKey.startsWith('0172002408011220') && hexKey.length === 80) {
    // Decode the hexadecimal key and return it as a Uint8Array
    return hex.decode(hexKey);
  }

  // Throw an error if IPNS key prefix is invalid
  throw new Error('Invalid IPNS Key Prefix: ' + hexKey);
}


// Generates an ed25519 pubkey from a seed and converts it to several IPNS pubkey formats
export async function getKeys(seed: Uint8Array) {
  // Check if seed length = 32 bytes
  if (seed.length != 32) throw new TypeError('Seed must be 32 bytes in length');
  // Generate ed25519 public key from seed
  const pubKey = await ed25519.getPublicKey(seed);
  // Create public key bytes by concatenating prefix bytes and pubKey
  const pubKeyBytes = concatBytes(
    new Uint8Array([0x01, 0x72, 0x00, 0x24, 0x08, 0x01, 0x12, 0x20]),
    pubKey
  );
  // Encode pubKeyBytes as a hex string and convert it to lowercase
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
