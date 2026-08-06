import Zen from "zen";
import type { KeyPair } from "./types.js";

// ponytail: KDF with Web Crypto API — no extra dependencies, browser-native PBKDF2.
// Weak passwords get computationally hardened before deriving the SEA identity.
//
// `iterations` is a parameter rather than a constant because the two callers must
// not move together: `deriveKeyPairFromPassword` derives an *identity*, so its
// count is frozen forever (changing it changes who you are), while the vault's
// count is recorded per-blob and can be raised for new vaults at any time.
async function kdf(
	password: string,
	salt: string,
	iterations = 100_000,
): Promise<ArrayBuffer> {
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
			iterations,
			hash: "SHA-256",
		},
		keyMaterial,
		256,
	);
}

function toHex(buf: ArrayBuffer | Uint8Array): string {
	return Array.from(new Uint8Array(buf))
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
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
	// 100_000 is load-bearing: it is what existing identities were derived with.
	const derived = await kdf(password, username, 100_000);
	const pair = await Zen.pair({ seed: toHex(derived) });
	return pair as KeyPair;
}

/**
 * Human-comparable fingerprint of a public key: SHA-256 truncated to 128 bits,
 * hex, grouped in fours.
 *
 * The server is what hands out peer keys, so possessing a key proves nothing
 * about whose it is — a malicious instance can serve its own and read every DM.
 * The fingerprint is short enough that two people can read it to each other out
 * of band, which is the only check the server cannot forge.
 */
export async function keyFingerprint(pub: string): Promise<string> {
	const digest = await crypto.subtle.digest(
		"SHA-256",
		new TextEncoder().encode(pub),
	);
	return toHex(digest)
		.slice(0, 32)
		.toUpperCase()
		.replace(/(.{4})(?=.)/g, "$1 ");
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
 *
 * The vault is the private half of the account's Zen identity, sealed under the
 * user's password and handed to the server as an opaque blob. The server cannot
 * open it, but it *holds* it — so the only thing standing between a database
 * dump and every user's identity is how expensive it is to guess the password.
 *
 * `Zen.encrypt(data, password)` alone is not that: its `aeskey()` is a single
 * SHA-256 over `password + salt`, so an offline attacker tests billions of
 * candidates per second on commodity GPUs. The password is stretched with
 * PBKDF2 first and Zen only ever sees the stretched key.
 *
 * Envelope: `tcv1:<iterations>:<saltHex>:<zenBlob>`. Zen's own output is base62
 * with `.` separators and never contains `:`, so the fields parse unambiguously.
 * Iterations and salt travel with the blob, so this count can be raised later
 * without invalidating vaults sealed under the old one.
 */
const VAULT_V1_PREFIX = "tcv1:";
const VAULT_KDF_ITERATIONS = 600_000;

async function vaultKey(
	passwordStr: string,
	salt: string,
	iterations: number,
): Promise<string> {
	return toHex(await kdf(passwordStr, salt, iterations));
}

export async function encryptPairVault(
	pair: KeyPair,
	passwordStr: string,
): Promise<string> {
	const salt = toHex(crypto.getRandomValues(new Uint8Array(16)));
	const key = await vaultKey(passwordStr, salt, VAULT_KDF_ITERATIONS);
	const encrypted = await Zen.encrypt(pair, key);
	return `${VAULT_V1_PREFIX}${VAULT_KDF_ITERATIONS}:${salt}:${encrypted}`;
}

export async function decryptPairVault(
	encryptedBlob: string,
	passwordStr: string,
): Promise<KeyPair | null> {
	try {
		let decrypted: unknown;

		if (encryptedBlob.startsWith(VAULT_V1_PREFIX)) {
			const rest = encryptedBlob.slice(VAULT_V1_PREFIX.length);
			const iterEnd = rest.indexOf(":");
			const saltEnd = rest.indexOf(":", iterEnd + 1);
			if (iterEnd < 1 || saltEnd < 0) return null;

			const iterations = Number(rest.slice(0, iterEnd));
			// A hostile server could otherwise hand back `iterations=1` and turn the
			// KDF back off for a password it wants to crack from the resulting blob.
			if (!Number.isInteger(iterations) || iterations < 100_000) return null;

			const key = await vaultKey(
				passwordStr,
				rest.slice(iterEnd + 1, saltEnd),
				iterations,
			);
			decrypted = await Zen.decrypt(rest.slice(saltEnd + 1), key);
		} else {
			// Legacy vault: the password went straight into Zen.encrypt. Readable so
			// nobody loses their identity on upgrade — `isLegacyPairVault` tells the
			// caller to re-seal it. Not a downgrade risk: an attacker who can swap in
			// an old-format blob already controls what the client decrypts.
			decrypted = await Zen.decrypt(encryptedBlob, passwordStr);
		}

		return decrypted ? (decrypted as KeyPair) : null;
	} catch {
		return null;
	}
}

/**
 * True when the blob predates the PBKDF2 envelope. Callers that hold the
 * password should re-seal and re-upload, so the weak copy stops existing.
 */
export function isLegacyPairVault(encryptedBlob: string): boolean {
	return !encryptedBlob.startsWith(VAULT_V1_PREFIX);
}
