export interface KeyPair {
  pub: string;
  priv: string;
  epub: string;
  epriv: string;
}

export interface PeerInfo {
  username: string;
  pubkey?: boolean;
  instance?: string;
}

export interface ChatMessage {
  from: string;
  text: string;
  ts: number;
  self?: boolean;
  lobby?: boolean;
  e2e?: boolean;
  to?: string;
  system?: boolean;
  instance?: string;
}

export type ChatStatus = 'offline' | 'connecting' | 'online';

export interface ChatClientOptions {
  serverUrl: string;
  token?: string;
  username?: string;
  instanceName?: string;
  autoConnect?: boolean;
  keyPair?: KeyPair;
}

export type MessageHandler = (msg: ChatMessage) => void;
export type PeersHandler = (peers: PeerInfo[]) => void;
export type StatusHandler = (status: ChatStatus) => void;

export interface RtcSignalMessage {
  from: string;
  fromSessionId?: string;
  to?: string;
  toSessionId?: string;
  signal: any;
}

export type RtcSignalHandler = (msg: RtcSignalMessage) => void;

/**
 * Utility to extract a clean instance name from a URL or hostname.
 * Example: 'https://sudorecords.tunecamp.net' -> 'sudorecords'
 */
export function extractInstanceName(url: string): string {
  if (!url) return '';
  try {
    const cleaned = url.replace(/^https?:\/\//i, '').replace(/^wss?:\/\//i, '').split('/')[0].split(':')[0];
    const parts = cleaned.split('.');
    if (parts.length >= 2 && parts[0].toLowerCase() !== 'www') {
      return parts[0];
    }
    return cleaned;
  } catch {
    return url;
  }
}

/**
 * Formats a username with its instance name appended in parentheses.
 * Example: ('admin', 'sudorecords') -> 'admin (sudorecords)'
 */
export function formatUsernameWithInstance(username: string, instance?: string): string {
  if (!username) return '';
  const cleanInst = instance?.trim();
  if (cleanInst && !username.includes('(')) {
    return `${username} (${cleanInst})`;
  }
  return username;
}
