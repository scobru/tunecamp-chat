import { generateKeyPair, encryptFor, decryptFrom } from './crypto.js';
import {
  extractInstanceName,
  formatUsernameWithInstance,
  type ChatMessage,
  type ChatStatus,
  type PeerInfo,
  type KeyPair,
  type MessageHandler,
  type PeersHandler,
  type StatusHandler
} from './types.js';

export class TuneCampChatClient {
  private serverUrl: string;
  private token?: string;
  private instanceName: string;
  private ws: WebSocket | null = null;
  private status: ChatStatus = 'offline';
  private keyPair: KeyPair;
  private peerKeys: Map<string, string> = new Map();
  private peers: PeerInfo[] = [];
  private messages: ChatMessage[] = [];
  private username = '';
  private isAdmin = false;

  private messageListeners: Set<MessageHandler> = new Set();
  private peersListeners: Set<PeersHandler> = new Set();
  private statusListeners: Set<StatusHandler> = new Set();

  private reconnectTimer: any = null;
  private pollTimer: any = null;
  private closedByUs = false;

  constructor(serverUrl: string, token?: string, customInstanceName?: string) {
    this.serverUrl = serverUrl.replace(/\/$/, '');
    this.token = token;
    this.instanceName = customInstanceName || extractInstanceName(this.serverUrl);
    this.keyPair = generateKeyPair();
  }

  public setCredentials(serverUrl: string, token?: string, customInstanceName?: string) {
    this.serverUrl = serverUrl.replace(/\/$/, '');
    this.token = token;
    this.instanceName = customInstanceName || extractInstanceName(this.serverUrl);
  }

  public getInstanceName(): string {
    return this.instanceName;
  }

  public getKeyPair(): KeyPair {
    return this.keyPair;
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

  private setStatus(newStatus: ChatStatus) {
    this.status = newStatus;
    this.statusListeners.forEach((fn) => fn(newStatus));
  }

  private notifyMessage(msg: ChatMessage) {
    const enrichedMsg: ChatMessage = {
      ...msg,
      instance: msg.instance || (msg.system ? undefined : this.instanceName)
    };
    this.messages = [...this.messages, enrichedMsg].slice(-200);
    this.messageListeners.forEach((fn) => fn(enrichedMsg));
  }

  private setPeersList(newPeers: PeerInfo[]) {
    const enrichedPeers = newPeers.map((p) => ({
      ...p,
      instance: p.instance || this.instanceName
    }));
    this.peers = enrichedPeers;
    this.peersListeners.forEach((fn) => fn(enrichedPeers));
  }

  public connect(): void {
    if (this.ws || this.status === 'connecting') return;
    this.closedByUs = false;
    this.setStatus('connecting');

    // Fetch initial chat history in background
    this.fetchHistory();

    const wsUrl = this.buildWsUrl();
    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onmessage = (event) => {
        let msg: any;
        try {
          msg = JSON.parse(event.data);
        } catch {
          return;
        }

        if (msg.type === 'auth_ok') {
          this.setStatus('online');
          this.username = msg.username || '';
          this.isAdmin = !!msg.isAdmin;
          if (msg.instance) this.instanceName = msg.instance;
          this.sendJson({ type: 'pubkey', pubkey: this.keyPair.publicKey });
          this.fetchPeers();
        } else if (msg.type === 'pubkey') {
          if (msg.from && msg.pubkey) {
            this.peerKeys.set(msg.from, msg.pubkey);
            if (!this.peers.some((p) => p.username === msg.from)) {
              this.setPeersList([...this.peers, { username: msg.from, pubkey: true, instance: msg.instance || this.instanceName }]);
            }
          }
        } else if (msg.type === 'system') {
          this.notifyMessage({
            from: 'System',
            text: msg.text,
            ts: msg.ts || Date.now(),
            lobby: true,
            system: true
          });
        } else if (msg.type === 'clear_history') {
          this.messages = [];
          this.notifyMessage({
            from: 'System',
            text: 'Chat history cleared by admin.',
            ts: Date.now(),
            lobby: true,
            system: true
          });
        } else if (msg.type === 'kicked') {
          this.notifyMessage({
            from: 'System',
            text: `You were kicked: ${msg.reason || 'Kicked by admin'}`,
            ts: Date.now(),
            lobby: true,
            system: true
          });
        } else if (msg.type === 'chat') {
          const msgInstance = msg.instance || this.instanceName;
          if (msg.lobby) {
            this.notifyMessage({
              from: msg.from,
              text: msg.text,
              ts: msg.ts || Date.now(),
              lobby: true,
              instance: msgInstance
            });
          } else {
            const senderKey = this.peerKeys.get(msg.from);
            const plain = senderKey
              ? decryptFrom(msg.text, senderKey, this.keyPair.secretKey)
              : null;
            this.notifyMessage({
              from: msg.from,
              text: plain ?? '[Encrypted message — key exchange pending]',
              ts: msg.ts || Date.now(),
              e2e: true,
              to: msg.from,
              instance: msgInstance
            });
          }
        }
      };

      this.ws.onclose = () => {
        this.setStatus('offline');
        this.ws = null;
        this.peerKeys.clear();
        this.setPeersList([]);
        if (!this.closedByUs) {
          this.reconnectTimer = setTimeout(() => this.connect(), 5000);
        }
      };

      this.ws.onerror = () => {
        this.ws?.close();
      };
    } catch {
      this.setStatus('offline');
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
    this.setStatus('offline');
    this.setPeersList([]);
  }

  public async fetchHistory(): Promise<ChatMessage[]> {
    if (!this.serverUrl) return [];
    try {
      const headers: Record<string, string> = {};
      if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
      const res = await fetch(`${this.serverUrl}/api/chat/history`, { headers });
      if (res.ok) {
        const data = (await res.json()) as any;
        const rawHistory: any[] = Array.isArray(data.messages)
          ? data.messages
          : Array.isArray(data)
          ? data
          : [];
        const formatted: ChatMessage[] = rawHistory.map((m: any) => ({
          from: m.username || m.from || 'Lobby',
          text: m.message || m.text || '',
          ts: m.created_at || m.ts || Date.now(),
          lobby: true,
          instance: m.instance || this.instanceName
        }));

        if (formatted.length > 0) {
          const existingTs = new Set(this.messages.map((m) => m.ts));
          const newItems = formatted.filter((m) => !existingTs.has(m.ts));
          if (newItems.length > 0) {
            this.messages = [...newItems, ...this.messages].slice(-200);
            if (this.messages.length > 0) {
              const lastMsg = this.messages[this.messages.length - 1];
              this.messageListeners.forEach((fn) => fn(lastMsg));
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
      const headers: Record<string, string> = {};
      if (this.token) headers['Authorization'] = `Bearer ${this.token}`;
      const res = await fetch(`${this.serverUrl}/api/chat/peers`, { headers });
      if (res.ok) {
        const data = (await res.json()) as any;
        const clients: PeerInfo[] = (
          Array.isArray(data.clients)
            ? data.clients
            : Array.isArray(data)
            ? data
            : []
        ).map((p: any) => ({
          ...p,
          instance: p.instance || this.instanceName
        }));
        this.setPeersList(clients);
        return clients;
      }
    } catch {
      /* ignore */
    }
    return this.peers;
  }

  public sendMessage(to: string, text: string): boolean {
    const cleanText = text.trim();
    if (!cleanText || this.status !== 'online' || !this.ws) return false;

    // IRC Moderation Slash commands
    if (cleanText.startsWith('/')) {
      return this.handleSlashCommand(cleanText);
    }

    let payload = cleanText;
    let isE2e = false;

    if (to) {
      const recipientKey = this.peerKeys.get(to);
      if (recipientKey) {
        payload = encryptFor(cleanText, recipientKey, this.keyPair.secretKey);
        isE2e = true;
      }
    }

    this.sendJson({ type: 'chat', to, text: payload });
    this.notifyMessage({
      from: to ? `→ ${to}` : '→ Lobby',
      text: cleanText,
      ts: Date.now(),
      self: true,
      lobby: !to,
      e2e: isE2e,
      to: to || undefined,
      instance: this.instanceName
    });
    return true;
  }

  private handleSlashCommand(commandStr: string): boolean {
    const parts = commandStr.slice(1).split(/\s+/);
    const cmd = parts[0]?.toLowerCase();
    const target = parts[1];
    const extra = parts.slice(2).join(' ');

    if (cmd === 'help') {
      this.notifyMessage({
        from: 'System',
        text: 'Available commands: /kick <user> [reason], /ban <user> [reason], /unban <user>, /mute <user> [minutes], /unmute <user>, /clear, /help',
        ts: Date.now(),
        lobby: true,
        system: true
      });
      return true;
    }

    if (['kick', 'ban', 'unban', 'mute', 'unmute', 'clear'].includes(cmd)) {
      if (!this.isAdmin) {
        this.notifyMessage({
          from: 'System',
          text: 'Error: Moderation commands are restricted to instance admins.',
          ts: Date.now(),
          lobby: true,
          system: true
        });
        return true;
      }

      if (cmd === 'clear') {
        this.sendAdminAction('clear');
      } else if (!target) {
        this.notifyMessage({
          from: 'System',
          text: `Usage: /${cmd} <username> [reason/minutes]`,
          ts: Date.now(),
          lobby: true,
          system: true
        });
      } else if (cmd === 'kick') {
        this.sendAdminAction('kick', target, extra || undefined);
      } else if (cmd === 'ban') {
        this.sendAdminAction('ban', target, extra || undefined);
      } else if (cmd === 'unban') {
        this.sendAdminAction('unban', target);
      } else if (cmd === 'mute') {
        const minutes = parseInt(parts[2], 10) || 15;
        const reason = parts.slice(3).join(' ') || undefined;
        this.sendAdminAction('mute', target, reason, minutes);
      } else if (cmd === 'unmute') {
        this.sendAdminAction('unmute', target);
      }
      return true;
    }
    return false;
  }

  public sendAdminAction(action: string, target?: string, reason?: string, duration?: number): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.sendJson({
        type: 'admin_action',
        action,
        target,
        reason,
        duration
      });
    }
  }

  private buildWsUrl(): string {
    const httpUrl = this.serverUrl;
    const wsProto = httpUrl.startsWith('https') ? 'wss' : 'ws';
    const cleanHost = httpUrl.replace(/^https?:\/\//, '');
    let url = `${wsProto}://${cleanHost}/ws/chat`;
    if (this.token) {
      url += `?token=${encodeURIComponent(this.token)}`;
    }
    return url;
  }

  private sendJson(data: any): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }
}
