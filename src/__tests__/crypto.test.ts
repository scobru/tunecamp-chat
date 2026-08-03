import { describe, it, expect } from "vitest";
import { generateKeyPair, encryptFor, decryptFrom } from "../crypto.js";
import { extractInstanceName, formatUsernameWithInstance } from "../types.js";

describe("TuneCamp Chat E2E Cryptography", () => {
	it("generates valid secp256k1 keypairs", async () => {
		const kp = await generateKeyPair();
		expect(kp.pub).toBeTypeOf("string");
		expect(kp.priv).toBeTypeOf("string");
		expect(kp.pub.length).toBeGreaterThan(10);
		expect(kp.priv.length).toBeGreaterThan(10);
	});

	it("encrypts and decrypts messages between two keypairs correctly", async () => {
		const alice = await generateKeyPair();
		const bob = await generateKeyPair();

		const plaintext = "Hello Bob, this is a secret E2EE message!";

		// Alice encrypts for Bob
		const ciphertext = await encryptFor(plaintext, bob.pub, alice);
		expect(ciphertext).not.toBe(plaintext);
		expect(ciphertext).toBeTypeOf("string");

		// Bob decrypts from Alice
		const decrypted = await decryptFrom(ciphertext, alice.pub, bob);
		expect(decrypted).toBe(plaintext);
	});

	it("returns null when trying to decrypt with an invalid key or tampered ciphertext", async () => {
		const alice = await generateKeyPair();
		const bob = await generateKeyPair();
		const eve = await generateKeyPair();

		const plaintext = "Top secret data";
		const ciphertext = await encryptFor(plaintext, bob.pub, alice);
		expect(ciphertext).not.toBe(plaintext);

		// Eve attempts to decrypt Alice's message to Bob using Eve's secret key
		const result = await decryptFrom(ciphertext, alice.pub, eve);
		expect(result).toBeNull();
	});
});

describe("Instance Name Utilities", () => {
	it("extracts instance name from server URLs correctly", () => {
		expect(extractInstanceName("https://sudorecords.tunecamp.net")).toBe(
			"sudorecords",
		);
		expect(extractInstanceName("http://radio.example.org:3000/")).toBe("radio");
		expect(extractInstanceName("https://sudorecords.com")).toBe("sudorecords");
	});

	it("formats username with instance name correctly", () => {
		expect(formatUsernameWithInstance("admin", "sudorecords")).toBe(
			"admin (sudorecords)",
		);
		expect(formatUsernameWithInstance("homoloto", "sudorecords")).toBe(
			"homoloto (sudorecords)",
		);
		expect(formatUsernameWithInstance("admin", "")).toBe("admin");
	});
});
