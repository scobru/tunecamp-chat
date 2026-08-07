import { describe, it, expect, vi, afterEach } from "vitest";
import { TuneCampChatClient } from "../client.js";

const ROOM_ROWS = [
	{ username: "carol", message: "third", created_at: 3000 },
	{ username: "bob", message: "second", created_at: 2000 },
	{ username: "alice", message: "first", created_at: 1000 },
];

function stubFetch(rows: unknown[]) {
	const fetchMock = vi.fn(async () => ({
		ok: true,
		json: async () => ({ messages: rows }),
	}));
	(globalThis as any).fetch = fetchMock;
	return fetchMock;
}

afterEach(() => {
	vi.restoreAllMocks();
	delete (globalThis as any).fetch;
});

describe("fetchRoomHistory", () => {
	it("merges the backlog into the store the socket feeds, oldest first", async () => {
		stubFetch(ROOM_ROWS);
		const client = new TuneCampChatClient("https://a.example.com");

		await client.fetchRoomHistory(7);

		expect(client.getMessages().map((m) => m.text)).toEqual([
			"first",
			"second",
			"third",
		]);
		expect(client.getMessages().every((m) => m.roomId === 7)).toBe(true);
		expect(client.getMessages().every((m) => m.lobby === false)).toBe(true);
	});

	it("does not duplicate rows already in the store", async () => {
		stubFetch(ROOM_ROWS);
		const client = new TuneCampChatClient("https://a.example.com");

		await client.fetchRoomHistory(7);
		await client.fetchRoomHistory(7);

		expect(client.getMessages()).toHaveLength(3);
	});

	it("keeps rooms apart when two of them share a timestamp", async () => {
		stubFetch([{ username: "alice", message: "in room 7", created_at: 1000 }]);
		const client = new TuneCampChatClient("https://a.example.com");
		await client.fetchRoomHistory(7);

		stubFetch([{ username: "alice", message: "in room 8", created_at: 1000 }]);
		await client.fetchRoomHistory(8);

		expect(client.getMessages()).toHaveLength(2);
		expect(client.getMessages().map((m) => m.roomId)).toEqual([8, 7]);
	});

	it("notifies listeners so a consumer re-reads the store", async () => {
		stubFetch(ROOM_ROWS);
		const client = new TuneCampChatClient("https://a.example.com");
		const seen = vi.fn();
		client.onMessage(seen);

		await client.fetchRoomHistory(7);

		expect(seen).toHaveBeenCalledTimes(1);
	});

	it("returns nothing and touches no listener when the room id is missing", async () => {
		const fetchMock = stubFetch(ROOM_ROWS);
		const client = new TuneCampChatClient("https://a.example.com");

		expect(await client.fetchRoomHistory(0)).toEqual([]);
		expect(fetchMock).not.toHaveBeenCalled();
		expect(client.getMessages()).toHaveLength(0);
	});
});
