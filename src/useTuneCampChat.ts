import { useState, useEffect, useRef, useCallback } from 'react';
import { TuneCampChatClient } from './client.js';
import { formatUsernameWithInstance } from './types.js';
import type { ChatMessage, ChatStatus, PeerInfo, RoomInfo, ChatClientOptions, KeyChangeEvent } from './types.js';

export function useTuneCampChat(
  options: ChatClientOptions,
  activePeer?: string,
  activeRoomId?: number,
) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [status, setStatus] = useState<ChatStatus>('offline');
  const [peers, setPeers] = useState<PeerInfo[]>([]);
  const [rooms, setRooms] = useState<RoomInfo[]>([]);
  const [unreadCounts, setUnreadCounts] = useState<Record<string, number>>({});
  const [roomUnreadCounts, setRoomUnreadCounts] = useState<Record<number, number>>({});
  const [username, setUsername] = useState<string>('');
  const [isAdmin, setIsAdmin] = useState<boolean>(false);
  // Peers whose key stopped matching the pinned one, keyed by peer id. DMs to
  // them are blocked until the user confirms the new fingerprint.
  const [keyChanges, setKeyChanges] = useState<Record<string, KeyChangeEvent>>({});

  const activePeerRef = useRef(activePeer);
  useEffect(() => {
    activePeerRef.current = activePeer;
    if (activePeer) {
      setUnreadCounts((prev) => ({ ...prev, [activePeer]: 0 }));
    }
  }, [activePeer]);

  const activeRoomRef = useRef(activeRoomId);
  useEffect(() => {
    activeRoomRef.current = activeRoomId;
    if (activeRoomId) {
      setRoomUnreadCounts((prev) => ({ ...prev, [activeRoomId]: 0 }));
    }
  }, [activeRoomId]);

  const clientRef = useRef<TuneCampChatClient | null>(null);

  useEffect(() => {
    if (!options.serverUrl) return;

    const client = new TuneCampChatClient(options.serverUrl, options.token, options.instanceName);
    if (options.keyPair) {
      client.initKeyPair(options.keyPair);
    }
    clientRef.current = client;

    const unsubStatus = client.onStatus((s) => {
      setStatus(s);
      setUsername(client.getUsername());
      setIsAdmin(client.getIsAdmin());
    });

    const unsubPeers = client.onPeers((p) => {
      setPeers(p);
    });

    const unsubKeyChange = client.onKeyChange((event) => {
      setKeyChanges((prev) => ({ ...prev, [event.peerId]: event }));
    });

    const unsubMsg = client.onMessage((msg) => {
      setMessages([...client.getMessages()]);
      if (msg.self) return;
      // A room message carries `lobby: false` like a DM does, so it has to be
      // routed by roomId first — otherwise it would count as an unread DM from
      // whoever happened to speak in the room.
      if (msg.roomId) {
        if (msg.roomId !== activeRoomRef.current) {
          setRoomUnreadCounts((prev) => ({
            ...prev,
            [msg.roomId as number]: (prev[msg.roomId as number] || 0) + 1
          }));
        }
        return;
      }
      if (!msg.lobby && msg.from && msg.from !== activePeerRef.current) {
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
      unsubKeyChange();
      unsubMsg();
      client.disconnect();
      clientRef.current = null;
    };
  }, [options.serverUrl, options.token, options.instanceName, options.autoConnect]);

  const sendMessage = useCallback((to: string, text: string) => {
    return clientRef.current?.sendMessage(to, text) ?? false;
  }, []);

  const refreshRooms = useCallback(async () => {
    const list = (await clientRef.current?.fetchRooms()) ?? [];
    setRooms(list);
    return list;
  }, []);

  // Rooms are listed for anyone; joining is what grants delivery. Refreshed on
  // connect because a room created while offline is otherwise invisible until
  // the consumer thinks to ask.
  useEffect(() => {
    if (status === 'online') void refreshRooms();
  }, [status, refreshRooms]);

  // Selecting a room subscribes the socket and pulls the backlog. Membership is
  // stored per user server-side, so joining an already-joined room is a no-op
  // and leaving is left to an explicit user action, not to deselecting.
  useEffect(() => {
    if (!activeRoomId || status !== 'online') return;
    const client = clientRef.current;
    if (!client) return;
    client.joinRoom(activeRoomId);
    void client.fetchRoomHistory(activeRoomId).then(() => {
      setMessages([...client.getMessages()]);
    });
  }, [activeRoomId, status]);

  const joinRoom = useCallback(async (roomId: number) => {
    if (!clientRef.current?.joinRoom(roomId)) return false;
    await refreshRooms();
    return true;
  }, [refreshRooms]);

  const leaveRoom = useCallback(async (roomId: number) => {
    if (!clientRef.current?.leaveRoom(roomId)) return false;
    await refreshRooms();
    return true;
  }, [refreshRooms]);

  const sendRoomMessage = useCallback((roomId: number, text: string) => {
    return clientRef.current?.sendRoomMessage(roomId, text) ?? false;
  }, []);

  const createRoom = useCallback(async (name: string, description?: string, isPrivate = false) => {
    const room = await clientRef.current?.createRoom(name, description, isPrivate);
    if (room) {
      // The creator is not a member by construction — joining is what puts the
      // room in their list and starts delivery.
      clientRef.current?.joinRoom(room.id);
      await refreshRooms();
    }
    return room ?? null;
  }, [refreshRooms]);

  const deleteRoom = useCallback(async (roomId: number) => {
    const ok = (await clientRef.current?.deleteRoom(roomId)) ?? false;
    if (ok) await refreshRooms();
    return ok;
  }, [refreshRooms]);

  const sendAdminAction = useCallback((action: string, target?: string, reason?: string, duration?: number) => {
    clientRef.current?.sendAdminAction(action, target, reason, duration);
  }, []);

  const clearUnread = useCallback((peer: string) => {
    setUnreadCounts((prev) => ({ ...prev, [peer]: 0 }));
  }, []);

  const clearRoomUnread = useCallback((roomId: number) => {
    setRoomUnreadCounts((prev) => ({ ...prev, [roomId]: 0 }));
  }, []);

  /**
   * Re-pin a peer to the key they now offer. Only call this from an explicit
   * user action taken after checking the fingerprint out of band.
   */
  const acceptKeyChange = useCallback((peerId: string) => {
    if (!clientRef.current?.acceptPeerKeyChange(peerId)) return false;
    setKeyChanges((prev) => {
      const next = { ...prev };
      delete next[peerId];
      return next;
    });
    return true;
  }, []);

  const getPeerFingerprint = useCallback((peerId: string) => {
    return clientRef.current?.getPeerFingerprint(peerId);
  }, []);

  const formatUser = useCallback((user: string, instance?: string) => {
    return formatUsernameWithInstance(user, instance || clientRef.current?.getInstanceName());
  }, []);

  const visibleMessages = activeRoomId
    ? messages.filter((m) => m.roomId === activeRoomId)
    : activePeer
      ? messages.filter(
          (m) =>
            m.lobby !== true &&
            !m.roomId &&
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
    rooms,
    refreshRooms,
    createRoom,
    deleteRoom,
    joinRoom,
    leaveRoom,
    sendRoomMessage,
    roomUnreadCounts,
    clearRoomUnread,
    keyChanges,
    acceptKeyChange,
    getPeerFingerprint,
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

