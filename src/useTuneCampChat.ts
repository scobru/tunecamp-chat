import { useState, useEffect, useRef, useCallback } from 'react';
import { TuneCampChatClient } from './client.js';
import { formatUsernameWithInstance } from './types.js';
import type { ChatMessage, ChatStatus, PeerInfo, ChatClientOptions } from './types.js';

export function useTuneCampChat(options: ChatClientOptions, activePeer?: string) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState<ChatStatus>('offline');
  const [peers, setPeers] = useState<PeerInfo[]>([]);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});
  const [username, setUsername] = useState<string>('');
  const [isAdmin, setIsAdmin] = useState<boolean>(false);

  const activePeerRef = useRef(activePeer);
  useEffect(() => {
    activePeerRef.current = activePeer;
    if (activePeer) {
      setUnreadCounts((prev) => ({ ...prev, [activePeer]: 0 }));
    }
  }, [activePeer]);

  const clientRef = useRef<TuneCampChatClient | null>(null);

  useEffect(() => {
    if (!options.serverUrl) return;

    const client = new TuneCampChatClient(options.serverUrl, options.token, options.instanceName);
    clientRef.current = client;

    const unsubStatus = client.onStatus((s) => {
      setStatus(s);
      setUsername(client.getUsername());
      setIsAdmin(client.getIsAdmin());
    });

    const unsubPeers = client.onPeers((p) => {
      setPeers(p);
    });

    const unsubMsg = client.onMessage((msg) => {
      setMessages([...client.getMessages()]);
      if (!msg.lobby && msg.from && msg.from !== activePeerRef.current && !msg.self) {
        setUnreadCounts((prev) => ({
          ...prev,
          [msg.from]: (prev[msg.from] || 0) + 1
        }));
      }
    });

    if (options.autoConnect !== false) {
      client.connect();
    }

    return () => {
      unsubStatus();
      unsubPeers();
      unsubMsg();
      client.disconnect();
      clientRef.current = null;
    };
  }, [options.serverUrl, options.token, options.instanceName, options.autoConnect]);

  const sendMessage = useCallback((to: string, text: string) => {
    return clientRef.current?.sendMessage(to, text) ?? false;
  }, []);

  const sendAdminAction = useCallback((action: string, target?: string, reason?: string, duration?: number) => {
    clientRef.current?.sendAdminAction(action, target, reason, duration);
  }, []);

  const clearUnread = useCallback((peer: string) => {
    setUnreadCounts((prev) => ({ ...prev, [peer]: 0 }));
  }, []);

  const formatUser = useCallback((user: string, instance?: string) => {
    return formatUsernameWithInstance(user, instance || clientRef.current?.getInstanceName());
  }, []);

  const visibleMessages = activePeer
    ? messages.filter(
        (m) =>
          m.lobby !== true &&
          (m.from === activePeer || (m.self && m.to === activePeer))
      )
    : messages.filter((m) => m.lobby !== false);

  const connect = useCallback(() => {
    clientRef.current?.connect();
  }, []);

  const disconnect = useCallback(() => {
    clientRef.current?.disconnect();
  }, []);

  return {
    messages: visibleMessages,
    allMessages: messages,
    status,
    username,
    isAdmin,
    peers,
    unreadCounts,
    clearUnread,
    sendMessage,
    sendAdminAction,
    formatUser,
    connect,
    disconnect,
    client: clientRef.current
  };
}

