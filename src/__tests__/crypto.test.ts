import { describe, it, expect } from "vitest";
import Zen from "zen";
import {
	generateKeyPair,
	encryptFor,
	decryptFrom,
	encryptPairVault,
	decryptPairVault,
	isLegacyPairVault,
	keyFingerprint,
} from "../crypto.js";
import { extractInstanceName, formatUsernameWithInstance } from "../types.js";
import type { KeyPinStore } from "../types.js";
import { TuneCampChatClient } from "../client.js";

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

describe("Password-sealed pair vault", () => {
	it("round-trips a pair and rejects the wrong password", async () => {
		const pair = await generateKeyPair();
		const vault = await encryptPairVault(pair, "correct horse battery staple");

		expect(vault).toMatch(/^tcv1:600000:[0-9a-f]{32}:/);
		expect(vault).not.toContain(pair.priv);

		const opened = await decryptPairVault(vault, "correct horse battery staple");
		expect(opened?.priv).toBe(pair.priv);
		expect(opened?.pub).toBe(pair.pub);

		expect(await decryptPairVault(vault, "wrong password")).toBeNull();
	});

	it("salts each vault, so the same pair and password never seal identically", async () => {
		const pair = await generateKeyPair();
		const a = await encryptPairVault(pair, "hunter2");
		const b = await encryptPairVault(pair, "hunter2");
		expect(a).not.toBe(b);
		expect((await decryptPairVault(b, "hunter2"))?.priv).toBe(pair.priv);
	});

	it("still opens legacy vaults and flags them for re-sealing", async () => {
		const pair = await generateKeyPair();
		// What the old code wrote: password handed straight to Zen.
		const legacy = await Zen.encrypt(pair, "hunter2");

		expect(isLegacyPairVault(legacy)).toBe(true);
		expect((await decryptPairVault(legacy, "hunter2"))?.priv).toBe(pair.priv);

		expect(isLegacyPairVault(await encryptPairVault(pair, "hunter2"))).toBe(false);
	});

	it("refuses a vault whose iteration count has been dialled down", async () => {
		const pair = await generateKeyPair();
		const vault = await encryptPairVault(pair, "hunter2");
		const weakened = vault.replace(/^tcv1:600000:/, "tcv1:1:");

		// A server that could pick the KDF cost could pick one it can brute-force.
		expect(await decryptPairVault(weakened, "hunter2")).toBeNull();
	});
});

describe("Peer key pinning (TOFU)", () => {
	function memoryPinStore(): KeyPinStore {
		const mem = new Map<string, string>();
		return {
			get: (id) => mem.get(id) ?? null,
			set: (id, fp) => void mem.set(id, fp),
			delete: (id) => void mem.delete(id),
		};
	}

	// installPeerKey is the internal gate every key goes through; the public
	// surface around it (pending change, accept, fingerprint) is exercised too.
	const install = (
		client: TuneCampChatClient,
		peerId: string,
		pub: string,
		source: "identity" | "session" = "session",
	): Promise<boolean> =>
		(client as any).installPeerKey(peerId, pub, source);

	it("produces a stable, human-readable fingerprint per key", async () => {
		const a = await generateKeyPair();
		const b = await generateKeyPair();

		const fp = await keyFingerprint(a.pub);
		expect(fp).toMatch(/^[0-9A-F]{4}( [0-9A-F]{4}){7}$/);
		expect(await keyFingerprint(a.pub)).toBe(fp);
		expect(await keyFingerprint(b.pub)).not.toBe(fp);
	});

	it("pins the first key seen and keeps accepting it", async () => {
		const client = new TuneCampChatClient("https://x.test", "t", "x", memoryPinStore());
		const alice = await generateKeyPair();

		expect(await install(client, "alice", alice.pub)).toBe(true);
		expect(client.getPeerFingerprint("alice")).toBe(await keyFingerprint(alice.pub));
		expect(await install(client, "alice", alice.pub)).toBe(true);
		expect(client.getPendingKeyChange("alice")).toBeUndefined();
	});

	it("refuses a substituted key, keeps the old one, and reports the swap", async () => {
		const client = new TuneCampChatClient("https://x.test", "t", "x", memoryPinStore());
		const alice = await generateKeyPair();
		const impostor = await generateKeyPair();

		const seen: any[] = [];
		client.onKeyChange((e) => seen.push(e));

		await install(client, "alice", alice.pub);
		expect(await install(client, "alice", impostor.pub)).toBe(false);

		// The pinned key stays in force — a swap must not take effect silently.
		expect(client.getPeerFingerprint("alice")).toBe(await keyFingerprint(alice.pub));

		const pending = client.getPendingKeyChange("alice");
		expect(pending?.pinned).toBe(await keyFingerprint(alice.pub));
		expect(pending?.offered).toBe(await keyFingerprint(impostor.pub));
		expect(seen).toHaveLength(1);
		expect(seen[0].peerId).toBe("alice");
	});

	it("adopts a new key only when the user explicitly accepts it", async () => {
		const client = new TuneCampChatClient("https://x.test", "t", "x", memoryPinStore());
		const alice = await generateKeyPair();
		const rotated = await generateKeyPair();

		await install(client, "alice", alice.pub);
		await install(client, "alice", rotated.pub);

		expect(client.acceptPeerKeyChange("alice")).toBe(true);
		expect(client.getPeerFingerprint("alice")).toBe(await keyFingerprint(rotated.pub));
		expect(client.getPendingKeyChange("alice")).toBeUndefined();
		// Re-pinned, so the same key no longer trips the check.
		expect(await install(client, "alice", rotated.pub)).toBe(true);
		expect(client.acceptPeerKeyChange("alice")).toBe(false);
	});

	it("carries pins across sessions, so a swap after a restart is still caught", async () => {
		const store = memoryPinStore();
		const alice = await generateKeyPair();
		const impostor = await generateKeyPair();

		const first = new TuneCampChatClient("https://x.test", "t", "x", store);
		await install(first, "alice", alice.pub);

		const afterRestart = new TuneCampChatClient("https://x.test", "t", "x", store);
		expect(await install(afterRestart, "alice", impostor.pub)).toBe(false);
		expect(await install(afterRestart, "alice", alice.pub)).toBe(true);
	});

	it("never lets a socket-announced key displace an account-bound one", async () => {
		const client = new TuneCampChatClient("https://x.test", "t", "x", memoryPinStore());
		const alice = await generateKeyPair();
		const impostor = await generateKeyPair();

		await install(client, "alice", alice.pub, "identity");
		expect(await install(client, "alice", impostor.pub, "session")).toBe(false);
		expect(client.getPeerKeySource("alice")).toBe("identity");
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
