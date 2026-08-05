import Zen from "zen";
import type { KeyPair } from "./types.js";

// ponytail: KDF with Web Crypto API — no extra dependencies, browser-native PBKDF2.
// Weak passwords get computationally hardened before deriving the SEA identity.
async function kdf(password: string, salt: string): Promise<ArrayBuffer> {
	const enc = new TextEncoder();
	const keyMaterial = await crypto.subtle.importKey(
		"raw",
		enc.encode(password),
		{ name: "PBKDF2" },
		false,
		["deriveBits"],
	);
	return crypto.subtle.deriveBits(
		{
			name: "PBKDF2",
			salt: enc.encode(salt),
			iterations: 100_000,
			hash: "SHA-256",
		},
		keyMaterial,
		256,
	);
}

export async function generateKeyPair(): Promise<KeyPair> {
	const pair = await Zen.pair();
	return pair as KeyPair;
}

/**
 * @deprecated Chat E2EE keys off the account's Zen identity now: generate a
 * random pair with `generateKeyPair()`, seal it with `encryptPairVault()` under
 * the user's password and store it server-side via POST /api/auth/zen/keys.
 *
 * A password-derived pair ties the identity to the password — changing the
 * password silently becomes a different person — and gives the recipient no way
 * to check the key belongs to the account. Kept only so existing sessions can
 * still read their cached pair while migrating.
 */
export async function deriveKeyPairFromPassword(
	username: string,
	password: string,
): Promise<KeyPair> {
	const derived = await kdf(password, username);
	const seedHex = Array.from(new Uint8Array(derived))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
	const pair = await Zen.pair({ seed: seedHex });
	return pair as KeyPair;
}

export async function encryptFor(
	text: string,
	recipientPub: string,
	myPair: KeyPair,
): Promise<string> {
	// Zen.secret derives a shared secret using ECDH
	const secret = await Zen.secret(recipientPub, myPair);
	// Zen.encrypt encrypts the message with the shared secret
	const encrypted = await Zen.encrypt(text, secret);
	return encrypted;
}

export async function decryptFrom(
	cipherText: string,
	senderPub: string,
	myPair: KeyPair,
): Promise<string | null> {
	try {
		const secret = await Zen.secret(senderPub, myPair);
		const decrypted = await Zen.decrypt(cipherText, secret);
		return typeof decrypted === "string" ? decrypted : null;
	} catch {
		return null;
	}
}

/**
 * Trustless E2EE Vault Functions
 */

export async function encryptPairVault(
	pair: KeyPair,
	passwordStr: string,
): Promise<string> {
	const encrypted = await Zen.encrypt(pair, passwordStr);
	return encrypted;
}

export async function decryptPairVault(
	encryptedBlob: string,
	passwordStr: string,
): Promise<KeyPair | null> {
	try {
		const decrypted = await Zen.decrypt(encryptedBlob, passwordStr);
		return decrypted ? (decrypted as KeyPair) : null;
	} catch {
		return null;
	}
}
