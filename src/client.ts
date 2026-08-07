import {
	generateKeyPair,
	encryptFor,
	decryptFrom,
	keyFingerprint,
} from "./crypto.js";
import {
	extractInstanceName,
	formatUsernameWithInstance,
	type ChatMessage,
	type ChatStatus,
	type PeerInfo,
	type RoomInfo,
	type KeyPair,
	type KeyPinStore,
	type KeyChangeEvent,
	type KeyChangeHandler,
	type MessageHandler,
	type PeersHandler,
	type StatusHandler,
	type RtcSignalHandler,
} from "./types.js";

const PIN_STORAGE_PREFIX = "tunecamp_chat_pin_";

function defaultPinStore(): KeyPinStore {
	try {
		if (typeof localStorage !== "undefined") {
			return {
				get: (id) => localStorage.getItem(PIN_STORAGE_PREFIX + id),
				set: (id, fp) => localStorage.setItem(PIN_STORAGE_PREFIX + id, fp),
				delete: (id) => localStorage.removeItem(PIN_STORAGE_PREFIX + id),
			};
		}
	} catch {
		/* private browsing or a locked-down origin — fall through to memory */
	}
	// Memory-only pins still catch a key swapping mid-session; they just can't
	// catch one that happens between runs.
	const mem = new Map<string, string>();
	return {
		get: (id) => mem.get(id) ?? null,
		set: (id, fp) => void mem.set(id, fp),
		delete: (id) => void mem.delete(id),
	};
}

export class TuneCampChatClient {
	private serverUrl: string;
	private token?: string;
	private instanceName: string;
	private ws: WebSocket | null = null;
	private status: ChatStatus = "offline";
	private keyPair: KeyPair;
	private peerKeys: Map<string, string> = new Map();
	private peerKeySources: Map<string, "identity" | "session"> = new Map();
	private peerFingerprints: Map<string, string> = new Map();
	private pinStore: KeyPinStore;
	/** Keys refused because they contradict a pin, awaiting the user's verdict. */
	private pendingKeyChanges: Map<
		string,
		KeyChangeEvent & { pubkey: string; source: "identity" | "session" }
	> = new Map();
	private peers: PeerInfo[] = [];
	private messages: ChatMessage[] = [];
	private username = "";
	private isAdmin = false;

	private messageListeners: Set<MessageHandler> = new Set();
	private peersListeners: Set<PeersHandler> = new Set();
	private statusListeners: Set<StatusHandler> = new Set();
	private rtcSignalListeners: Set<RtcSignalHandler> = new Set();
	private keyChangeListeners: Set<KeyChangeHandler> = new Set();

	private reconnectTimer: any = null;
	private pollTimer: any = null;
	private closedByUs = false;

	constructor(
		serverUrl: string,
		token?: string,
		customInstanceName?: string,
		pinStore?: KeyPinStore,
	) {
		this.serverUrl = serverUrl.replace(/\/$/, "");
		this.token = token;
		this.instanceName =
			customInstanceName || extractInstanceName(this.serverUrl);
		this.keyPair = { pub: "", priv: "" };
		this.pinStore = pinStore ?? defaultPinStore();
	}

	public async initKeyPair(existingPair?: KeyPair) {
		if (existingPair) {
			this.keyPair = existingPair;
		} else if (!this.keyPair.pub) {
			this.keyPair = await generateKeyPair();
		}
	}

	public setCredentials(
		serverUrl: string,
		token?: string,
		customInstanceName?: string,
	) {
		this.serverUrl = serverUrl.replace(/\/$/, "");
		this.token = token;
		this.instanceName =
			customInstanceName || extractInstanceName(this.serverUrl);
	}

	public getInstanceName(): string {
		return this.instanceName;
	}

	public getKeyPair(): KeyPair {
		return this.keyPair;
	}

	/**
	 * Where a peer's key came from: `identity` is bound to their account and the
	 * same on every instance, `session` is trust-on-first-use from a live socket.
	 * `undefined` means we have no key for them yet.
	 */
	public getPeerKeySource(
		username: string,
	): "identity" | "session" | undefined {
		return this.peerKeySources.get(username);
	}

	/**
	 * Install a peer's key, subject to trust-on-first-use pinning. Returns false
	 * when the key is refused.
	 *
	 * The first key seen for a peer is pinned. A later key with a different
	 * fingerprint is quarantined rather than used: the server chooses which key it
	 * hands out, so a silent substitution is indistinguishable from a wiretap.
	 * Only the user, having compared the new fingerprint out of band, can clear it
	 * via `acceptPeerKeyChange`.
	 */
	private async installPeerKey(
		peerId: string,
		pubkey: string,
		source: "identity" | "session",
	): Promise<boolean> {
		// A key merely announced over a socket must never displace one resolved
		// from the account's Zen identity — that is a downgrade to an
		// unverifiable key, and the server can trigger it at will.
		if (source === "session" && this.peerKeySources.get(peerId) === "identity")
			return false;

		const offered = await keyFingerprint(pubkey);
		const pinned = this.pinStore.get(peerId);

		if (pinned && pinned !== offered) {
			this.pendingKeyChanges.set(peerId, {
				peerId,
				pinned,
				offered,
				pubkey,
				source,
			});
			this.keyChangeListeners.forEach((fn) =>
				fn({ peerId, pinned, offered }),
			);
			return false;
		}

		if (!pinned) this.pinStore.set(peerId, offered);
		this.pendingKeyChanges.delete(peerId);
		this.peerKeys.set(peerId, pubkey);
		this.peerKeySources.set(peerId, source);
		this.peerFingerprints.set(peerId, offered);
		return true;
	}

	/** Fingerprint in use for a peer, for the user to read out of band. */
	public getPeerFingerprint(peerId: string): string | undefined {
		return this.peerFingerprints.get(peerId);
	}

	/** Set when this peer offered a key that contradicts the pinned one. */
	public getPendingKeyChange(peerId: string): KeyChangeEvent | undefined {
		const pending = this.pendingKeyChanges.get(peerId);
		return pending
			? { peerId: pending.peerId, pinned: pending.pinned, offered: pending.offered }
			: undefined;
	}

	/**
	 * Re-pin a peer to the key they now offer. Call this only on an explicit user
	 * action taken after comparing fingerprints over a channel this server does
	 * not control — clicking it away on the server's say-so defeats the pin.
	 */
	public acceptPeerKeyChange(peerId: string): boolean {
		const pending = this.pendingKeyChanges.get(peerId);
		if (!pending) return false;
		this.pinStore.set(peerId, pending.offered);
		this.pendingKeyChanges.delete(peerId);
		this.peerKeys.set(peerId, pending.pubkey);
		this.peerKeySources.set(peerId, pending.source);
		this.peerFingerprints.set(peerId, pending.offered);
		return true;
	}

	public onKeyChange(handler: KeyChangeHandler): () => void {
		this.keyChangeListeners.add(handler);
		return () => this.keyChangeListeners.delete(handler);
	}

	public getStatus(): ChatStatus {
		return this.status;
	}

	public getPeers(): PeerInfo[] {
		return this.peers;
	}

	public getMessages(): ChatMessage[] {
		return this.messages;
	}

	public getUsername(): string {
		return this.username;
	}

	public getFormattedUsername(username?: string, instance?: string): string {
		const user = username || this.username;
		const inst = instance || this.instanceName;
		return formatUsernameWithInstance(user, inst);
	}

	public getIsAdmin(): boolean {
		return this.isAdmin;
	}

	private async ensurePeerKey(
		username: string,
		instance: string,
	): Promise<string | undefined> {
		const cacheKey = `${username}@${instance}`;
		const cached = this.peerKeys.get(cacheKey);
		if (cached) return cached;

		try {
			const headers: Record<string, string> = {};
			if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
			const res = await fetch(
				`${this.serverUrl}/api/chat/pubkey/${encodeURIComponent(username)}?instance=${encodeURIComponent(instance)}`,
				{ headers },
			);
			if (res.ok) {
				const data = (await res.json()) as any;
				if (data.pubkey) {
					// `identity` keys are bound to the account and identical on every
					// instance, so the user can check one out of band. `session` keys
					// are whatever a socket announced — remember which we got so the
					// UI can say so instead of implying both are equally trusted.
					const accepted = await this.installPeerKey(
						cacheKey,
						data.pubkey,
						data.source === "identity" ? "identity" : "session",
					);
					return accepted ? data.pubkey : undefined;
				}
			}
		} catch {
			/* ignore */
		}
		return undefined;
	}

	public onMessage(handler: MessageHandler): () => void {
		this.messageListeners.add(handler);
		return () => this.messageListeners.delete(handler);
	}

	public onPeers(handler: PeersHandler): () => void {
		this.peersListeners.add(handler);
		return () => this.peersListeners.delete(handler);
	}

	public onStatus(handler: StatusHandler): () => void {
		this.statusListeners.add(handler);
		return () => this.statusListeners.delete(handler);
	}

	public onRtcSignal(handler: RtcSignalHandler): () => void {
		this.rtcSignalListeners.add(handler);
		return () => this.rtcSignalListeners.delete(handler);
	}

	public sendRtcSignal(to: string, signal: any): boolean {
		if (this.ws?.readyState === WebSocket.OPEN) {
			this.sendJson({
				type: "rtc_signal",
				to,
				signal,
			});
			return true;
		}
		return false;
	}

	private setStatus(newStatus: ChatStatus) {
		this.status = newStatus;
		this.statusListeners.forEach((fn) => fn(newStatus));
	}

	private notifyMessage(msg: ChatMessage) {
		const enrichedMsg: ChatMessage = {
			...msg,
			instance: msg.instance || (msg.system ? undefined : this.instanceName),
		};
		this.messages = [...this.messages, enrichedMsg].slice(-200);
		this.messageListeners.forEach((fn) => fn(enrichedMsg));
	}

	private setPeersList(newPeers: PeerInfo[]) {
		const enrichedPeers = newPeers.map((p) => ({
			...p,
			instance: p.instance || this.instanceName,
		}));
		this.peers = enrichedPeers;
		this.peersListeners.forEach((fn) => fn(enrichedPeers));
	}

	public connect(): void {
		if (this.ws || this.status === "connecting") return;
		this.closedByUs = false;
		this.setStatus("connecting");

		// ponytail: chat additivo — genera la coppia al primo uso, senza bloccare il login.
		// Se non c'è ancora una chiave, parte senza E2EE e si aggiorna dopo.
		this.initKeyPair().catch(() => {});

		// Fetch initial chat history in background
		this.fetchHistory();

		const wsUrl = this.buildWsUrl();
		try {
			this.ws = new WebSocket(wsUrl);

			this.ws.onmessage = async (event) => {
				let msg: any;
				try {
					msg = JSON.parse(event.data);
				} catch {
					return;
				}

				if (msg.type === "auth_ok") {
					this.setStatus("online");
					this.username = msg.username || "";
					this.isAdmin = !!msg.isAdmin;
					if (msg.instance) this.instanceName = msg.instance;
					this.sendJson({ type: "pubkey", pubkey: this.keyPair.pub });
					this.fetchPeers();
				} else if (msg.type === "pubkey") {
					if (msg.from && msg.pubkey) {
						await this.installPeerKey(msg.from, msg.pubkey, "session");
						if (!this.peers.some((p) => p.username === msg.from)) {
							this.setPeersList([
								...this.peers,
								{
									username: msg.from,
									pubkey: true,
									instance: msg.instance || this.instanceName,
								},
							]);
						}
					}
				} else if (msg.type === "system") {
					this.notifyMessage({
						from: "System",
						text: msg.text,
						ts: msg.ts || Date.now(),
						lobby: true,
						system: true,
					});
				} else if (msg.type === "clear_history") {
					this.messages = [];
					this.notifyMessage({
						from: "System",
						text: "Chat history cleared by admin.",
						ts: Date.now(),
						lobby: true,
						system: true,
					});
				} else if (msg.type === "kicked") {
					this.notifyMessage({
						from: "System",
						text: msg.reason || "Kicked",
						ts: msg.ts || Date.now(),
						lobby: true,
						system: true,
					});
				} else if (msg.type === "chat") {
					if (msg.lobby) {
						this.notifyMessage({
							from: msg.from,
							text: msg.text,
							ts: msg.ts || Date.now(),
							lobby: true,
							instance: msg.instance || this.instanceName,
						});
					} else {
						const senderKey = this.peerKeys.get(msg.from);
						const plain = senderKey
							? await decryptFrom(msg.text, senderKey, this.keyPair)
							: null;
						this.notifyMessage({
							from: msg.from,
							text: plain ?? "[Encrypted message — key exchange pending]",
							ts: msg.ts || Date.now(),
							e2e: true,
							to: msg.from,
							instance: msg.instance || this.instanceName,
						});
					}
				} else if (msg.type === "room_chat") {
					this.notifyMessage({
						from: msg.from,
						text: msg.text,
						ts: msg.ts || Date.now(),
						lobby: false,
						roomId: msg.roomId,
						roomGlobalId: msg.roomGlobalId,
						instance: msg.instance || this.instanceName,
					});
				}
			};

			this.ws.onopen = () => {
				this.setStatus("connecting");
				this.sendJson({
					type: "auth",
					token: this.token,
					pubkey: this.keyPair.pub,
				});
			};

			this.ws.onclose = () => {
				this.setStatus("offline");
				this.ws = null;
				this.peerKeys.clear();
				this.peerKeySources.clear();
				this.peerFingerprints.clear();
				// pendingKeyChanges deliberately survives: a key-change warning must
				// not be cleared by a reconnect the server can cause at will.
				this.setPeersList([]);
				if (!this.closedByUs) {
					this.reconnectTimer = setTimeout(() => this.connect(), 5000);
				}
			};

			this.ws.onerror = () => {
				this.ws?.close();
			};
		} catch {
			this.setStatus("offline");
		}

		if (!this.pollTimer) {
			this.pollTimer = setInterval(() => this.fetchPeers(), 5000);
		}
	}

	public disconnect(): void {
		this.closedByUs = true;
		if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
		if (this.pollTimer) clearInterval(this.pollTimer);
		this.reconnectTimer = null;
		this.pollTimer = null;
		if (this.ws) {
			this.ws.close();
			this.ws = null;
		}
		this.setStatus("offline");
		this.setPeersList([]);
	}

	public async fetchHistory(): Promise<ChatMessage[]> {
		if (!this.serverUrl) return [];
		try {
			const res = await fetch(`${this.serverUrl}/api/chat/history`, {
				headers: this.authHeaders(),
			});
			if (res.ok) {
				const data = (await res.json()) as any;
				const rawHistory: any[] = Array.isArray(data.messages)
					? data.messages
					: Array.isArray(data)
						? data
						: [];
				const formatted: ChatMessage[] = rawHistory.map((m: any) => ({
					from: m.username || m.from || "Lobby",
					text: m.message || m.text || "",
					ts: m.created_at || m.ts || Date.now(),
					lobby: true,
					instance: m.instance || this.instanceName,
				}));

				if (formatted.length > 0) {
					const existingTs = new Set(this.messages.map((m) => m.ts));
					const newItems = formatted.filter((m) => !existingTs.has(m.ts));
					if (newItems.length > 0) {
						this.messages = [...newItems, ...this.messages].slice(-200);
						if (this.messages.length > 0) {
							const lastMsg = this.messages[this.messages.length - 1];
							for (const fn of this.messageListeners) {
								fn(lastMsg);
							}
						}
					}
				}
				return formatted;
			}
		} catch {
			/* ignore */
		}
		return [];
	}

	public async fetchPeers(): Promise<PeerInfo[]> {
		if (!this.serverUrl) return [];
		try {
			const res = await fetch(`${this.serverUrl}/api/chat/peers`, {
				headers: this.authHeaders(),
			});
			if (res.ok) {
				const data = (await res.json()) as any;
				const parsedClients = Array.isArray(data.clients)
					? data.clients
					: Array.isArray(data)
						? data
						: [];
				const clients: PeerInfo[] = parsedClients.map((p: any) => ({
					...p,
					instance: p.instance || this.instanceName,
				}));
				this.setPeersList(clients);
				return clients;
			}
		} catch {
			/* ignore */
		}
		return this.peers;
	}

	public async sendMessage(to: string, text: string): Promise<boolean> {
		const cleanText = text.trim();
		if (!cleanText || this.status !== "online" || !this.ws) return false;

		// IRC Moderation Slash commands
		if (cleanText.startsWith("/")) {
			return this.handleSlashCommand(cleanText);
		}

		let payload = cleanText;
		let isE2e = false;

		if (to) {
			// `ensurePeerKey` caches under `user@instance`, which is what `to`
			// already is for a remote peer, so both paths share one pin id.
			let recipientKey: string | undefined;
			if (!this.pendingKeyChanges.has(to)) {
				if (to.includes("@")) {
					const [remoteUsername, remoteInstance] = to.split("@");
					recipientKey = await this.ensurePeerKey(
						remoteUsername,
						remoteInstance,
					);
				} else {
					recipientKey = this.peerKeys.get(to);
				}
			}

			if (!recipientKey) {
				// A DM with no usable key used to go out in the clear, which the
				// sender had no way to notice. Refusing is the only outcome that
				// can't be provoked by the server simply withholding a key.
				const pending = this.pendingKeyChanges.get(to);
				this.notifyMessage({
					from: "System",
					text: pending
						? `${to}'s encryption key changed (${pending.pinned} → ${pending.offered}). Message not sent. Verify the new fingerprint with them over a channel this server doesn't control, then accept the change.`
						: `No encryption key for ${to} yet — message not sent rather than sent unencrypted.`,
					ts: Date.now(),
					lobby: false,
					system: true,
					to,
				});
				return false;
			}

			payload = await encryptFor(cleanText, recipientKey, this.keyPair);
			isE2e = true;
		}

		this.sendJson({ type: "chat", to, text: payload });
		this.notifyMessage({
			from: to ? `→ ${to}` : "→ Lobby",
			text: cleanText,
			ts: Date.now(),
			self: true,
			lobby: !to,
			e2e: isE2e,
			to: to || undefined,
			instance: this.instanceName,
		});
		return true;
	}

	private handleSlashCommand(commandStr: string): boolean {
		const parts = commandStr.slice(1).split(/\s+/);
		const cmd = parts[0]?.toLowerCase();
		const target = parts[1];
		const extra = parts.slice(2).join(" ");

		if (cmd === "help") {
			this.notifyMessage({
				from: "System",
				text: "Available commands: /kick <user> [reason], /ban <user> [reason], /unban <user>, /mute <user> [minutes], /unmute <user>, /clear, /help",
				ts: Date.now(),
				lobby: true,
				system: true,
			});
			return true;
		}

		if (["kick", "ban", "unban", "mute", "unmute", "clear"].includes(cmd)) {
			if (!this.isAdmin) {
				this.notifyMessage({
					from: "System",
					text: "Error: Moderation commands are restricted to instance admins.",
					ts: Date.now(),
					lobby: true,
					system: true,
				});
				return true;
			}

			if (cmd === "clear") {
				this.sendAdminAction("clear");
			} else if (!target) {
				this.notifyMessage({
					from: "System",
					text: `Usage: /${cmd} <username> [reason/minutes]`,
					ts: Date.now(),
					lobby: true,
					system: true,
				});
			} else if (cmd === "kick") {
				this.sendAdminAction("kick", target, extra || undefined);
			} else if (cmd === "ban") {
				this.sendAdminAction("ban", target, extra || undefined);
			} else if (cmd === "unban") {
				this.sendAdminAction("unban", target);
			} else if (cmd === "mute") {
				const minutes = parseInt(parts[2], 10) || 15;
				const reason = parts.slice(3).join(" ") || undefined;
				this.sendAdminAction("mute", target, reason, minutes);
			} else if (cmd === "unmute") {
				this.sendAdminAction("unmute", target);
			}
			return true;
		}
		return false;
	}

	public sendAdminAction(
		action: string,
		target?: string,
		reason?: string,
		duration?: number,
	): void {
		if (this.ws?.readyState === WebSocket.OPEN) {
			this.sendJson({
				type: "admin_action",
				action,
				target,
				reason,
				duration,
			});
		}
	}

	private buildWsUrl(): string {
		const httpUrl = this.serverUrl;
		const wsProto = httpUrl.startsWith("https") ? "wss" : "ws";
		const cleanHost = httpUrl.replace(/^https?:\/\//, "");
		let url = `${wsProto}://${cleanHost}/ws/chat`;
		if (this.token) {
			url += `?token=${encodeURIComponent(this.token)}`;
		}
		return url;
	}

	// --- Rooms -------------------------------------------------------------
	// Rooms are addressed by the instance-local numeric id the server assigns.
	// Cross-instance routing is the server's job (global_id), not the client's.

	public joinRoom(roomId: number): boolean {
		if (!roomId || this.ws?.readyState !== WebSocket.OPEN) return false;
		this.sendJson({ type: "room_join", roomId });
		return true;
	}

	public leaveRoom(roomId: number): boolean {
		if (!roomId || this.ws?.readyState !== WebSocket.OPEN) return false;
		this.sendJson({ type: "room_leave", roomId });
		return true;
	}

	public sendRoomMessage(roomId: number, text: string): boolean {
		const clean = String(text ?? "").trim();
		if (!roomId || !clean || this.ws?.readyState !== WebSocket.OPEN)
			return false;
		this.sendJson({ type: "room_chat", roomId, text: clean });
		this.notifyMessage({
			from: this.username,
			text: clean,
			ts: Date.now(),
			self: true,
			lobby: false,
			roomId,
			instance: this.instanceName,
		});
		return true;
	}

	public async fetchRooms(): Promise<RoomInfo[]> {
		if (!this.serverUrl) return [];
		try {
			const res = await fetch(`${this.serverUrl}/api/chat/rooms`, {
				headers: this.authHeaders(),
			});
			if (res.ok) {
				const data = (await res.json()) as any;
				return Array.isArray(data.rooms) ? (data.rooms as RoomInfo[]) : [];
			}
		} catch {
			/* ignore */
		}
		return [];
	}

	public async createRoom(
		name: string,
		description?: string,
		isPrivate = false,
	): Promise<RoomInfo | null> {
		if (!this.serverUrl || !name?.trim()) return null;
		try {
			const res = await fetch(`${this.serverUrl}/api/chat/rooms`, {
				method: "POST",
				headers: { "Content-Type": "application/json", ...this.authHeaders() },
				body: JSON.stringify({
					name,
					description: description ?? null,
					is_private: isPrivate,
				}),
			});
			if (res.ok) return (await res.json()) as RoomInfo;
		} catch {
			/* ignore */
		}
		return null;
	}

	/**
	 * Room backlog, merged into the same store the socket feeds so a consumer
	 * reading `getMessages()` sees one ordered history instead of having to
	 * stitch REST and socket traffic together itself. The server returns newest
	 * first; the store is oldest first, so the rows are reversed on the way in.
	 */
	public async fetchRoomHistory(
		roomId: number,
		limit = 100,
	): Promise<ChatMessage[]> {
		if (!this.serverUrl || !roomId) return [];
		try {
			const res = await fetch(
				`${this.serverUrl}/api/chat/rooms/${roomId}/messages?limit=${limit}`,
				{ headers: this.authHeaders() },
			);
			if (res.ok) {
				const data = (await res.json()) as any;
				const rows = Array.isArray(data.messages) ? data.messages : [];
				const formatted: ChatMessage[] = rows
					.map((m: any) => ({
						from: m.username || m.from || "Room",
						text: m.message || m.text || "",
						ts: m.created_at || m.ts || Date.now(),
						lobby: false,
						roomId,
						instance: m.instance || this.instanceName,
					}))
					.reverse();
				this.mergeRoomHistory(formatted);
				return formatted;
			}
		} catch {
			/* ignore */
		}
		return [];
	}

	/**
	 * Two rooms can legitimately carry the same timestamp, so identity here is
	 * room + sender + ts rather than the ts alone the lobby merge relies on.
	 */
	private mergeRoomHistory(history: ChatMessage[]) {
		if (history.length === 0) return;
		const seen = new Set(
			this.messages.map((m) => `${m.roomId ?? ""}|${m.from}|${m.ts}`),
		);
		const newItems = history.filter(
			(m) => !seen.has(`${m.roomId ?? ""}|${m.from}|${m.ts}`),
		);
		if (newItems.length === 0) return;
		this.messages = [...newItems, ...this.messages].slice(-200);
		const last = this.messages[this.messages.length - 1];
		for (const fn of this.messageListeners) fn(last);
	}

	public async fetchRoomMembers(roomId: number): Promise<string[]> {
		if (!this.serverUrl || !roomId) return [];
		try {
			const res = await fetch(
				`${this.serverUrl}/api/chat/rooms/${roomId}/members`,
				{ headers: this.authHeaders() },
			);
			if (res.ok) {
				const data = (await res.json()) as any;
				return Array.isArray(data.members) ? data.members : [];
			}
		} catch {
			/* ignore */
		}
		return [];
	}

	public async deleteRoom(roomId: number): Promise<boolean> {
		if (!this.serverUrl || !roomId) return false;
		try {
			const res = await fetch(`${this.serverUrl}/api/chat/rooms/${roomId}`, {
				method: "DELETE",
				headers: this.authHeaders(),
			});
			return res.ok;
		} catch {
			/* ignore */
		}
		return false;
	}

	private authHeaders(): Record<string, string> {
		const headers: Record<string, string> = {};
		if (this.token) headers["Authorization"] = `Bearer ${this.token}`;
		return headers;
	}

	private sendJson(data: any): void {
		if (this.ws?.readyState === WebSocket.OPEN) {
			this.ws.send(JSON.stringify(data));
		}
	}
}
