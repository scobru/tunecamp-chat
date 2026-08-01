# 💬 `@tunecamp/chat` (`tunecamp-chat`)

Essential, lightweight E2EE chat client library and React hook for the **TuneCamp** ecosystem (used by **Sidecamp** and **TuneCamp Instance**).

---

## 🚀 Features

- 🔒 **Curve25519 E2E Encryption**: Lightweight 1:1 message encryption via `tweetnacl`.
- 🌐 **WebSocket Transport**: Automatic connection and reconnection to `/ws/chat`.
- 👥 **Roster Management**: Automatic peer discovery & polling via `GET /api/chat/peers`.
- 🛠️ **IRC Slash Commands & Admin Moderation**: Native support for `/kick`, `/ban`, `/unban`, `/mute`, `/unmute`, `/clear`, `/help`.
- ⚛️ **React Hook Included**: Includes `useTuneCampChat` for single-line integration in React/Next.js apps.

---

## 📦 Usage

### With React (`useTuneCampChat`)

```tsx
import { useTuneCampChat } from '@tunecamp/chat';

function ChatComponent() {
  const { messages, peers, unreadCounts, sendMessage } = useTuneCampChat({
    serverUrl: 'https://instance.tunecamp.net',
    token: 'USER_JWT_TOKEN'
  }, activePeerUsername);

  return (
    <div>
      {messages.map((m, i) => (
        <div key={i}>{m.from}: {m.text}</div>
      ))}
      <button onClick={() => sendMessage(activePeerUsername, 'Hello!')}>Send</button>
    </div>
  );
}
```

### Pure TypeScript / Node / Framework Agnostic (`TuneCampChatClient`)

```typescript
import { TuneCampChatClient } from '@tunecamp/chat';

const client = new TuneCampChatClient('https://instance.tunecamp.net', 'TOKEN');
client.onMessage((msg) => {
  console.log('New message:', msg);
});

client.connect();
client.sendMessage('', 'Hello Lobby!');
```

---

## 📄 License

MIT © TuneCamp
