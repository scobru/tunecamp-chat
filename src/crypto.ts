import nacl from 'tweetnacl';
import type { KeyPair } from './types.js';

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8');

export function encodeBase64(arr: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < arr.length; i++) {
    binary += String.fromCharCode(arr[i]);
  }
  return btoa(binary);
}

export function decodeBase64(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function encodeUTF8(arr: Uint8Array): string {
  return decoder.decode(arr);
}

export function decodeUTF8(str: string): Uint8Array {
  return encoder.encode(str);
}

export function generateKeyPair(): KeyPair {
  const kp = nacl.box.keyPair();
  return {
    publicKey: encodeBase64(kp.publicKey),
    secretKey: encodeBase64(kp.secretKey)
  };
}

export function encryptFor(text: string, recipientPublicKeyB64: string, mySecretKeyB64: string): string {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const box = nacl.box(
    decodeUTF8(text),
    nonce,
    decodeBase64(recipientPublicKeyB64),
    decodeBase64(mySecretKeyB64)
  );
  const full = new Uint8Array(nonce.length + box.length);
  full.set(nonce);
  full.set(box, nonce.length);
  return encodeBase64(full);
}

export function decryptFrom(cipherB64: string, senderPublicKeyB64: string, mySecretKeyB64: string): string | null {
  try {
    const full = decodeBase64(cipherB64);
    const nonce = full.slice(0, nacl.box.nonceLength);
    const box = full.slice(nacl.box.nonceLength);
    const opened = nacl.box.open(
      box,
      nonce,
      decodeBase64(senderPublicKeyB64),
      decodeBase64(mySecretKeyB64)
    );
    return opened ? encodeUTF8(opened) : null;
  } catch {
    return null;
  }
}
