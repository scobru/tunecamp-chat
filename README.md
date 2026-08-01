# 💬 `@tunecamp/chat` (`tunecamp-chat`)

Essential, lightweight E2EE chat client library, instance domain labeler, and React hook for the **TuneCamp** ecosystem (used by **Sidecamp** and **TuneCamp Instance**).

---

## 🚀 Features

- 🔒 **Curve25519 E2E Encryption**: Lightweight 1:1 message encryption using native Web `TextEncoder` & `tweetnacl`.
- 🏷️ **Instance Domain Labels**: Automatically extracts and appends instance domain tags to user nicknames (e.g. `admin (sudorecords)`).
- 📜 **Chat History Loading**: Automatic REST backlog hydration via `GET /api/chat/history`.
- 🌐 **WebSocket Transport**: Automatic connection and reconnection lifecycle on `/ws/chat`.
- 👥 **Roster Management**: Automatic peer discovery & polling via `GET /api/chat/peers`.
- 🛠️ **IRC Slash Commands & Moderation**: Native support for `/kick`, `/ban`, `/unban`, `/mute`, `/unmute`, `/clear`, `/help`.
- ⚛️ **React Hook Included**: Includes `useTuneCampChat` for single-line integration in React apps.

---

## 📦 Installation

Add `@tunecamp/chat` to your `package.json`:

```json
"dependencies": {
  "@tunecamp/chat": "github:scobru/tunecamp-chat"
}
```

---

## 💻 Usage

### With React (`useTuneCampChat`)

```tsx
import { useTuneCampChat } from '@tunecamp/chat';

function ChatComponent() {
  const { messages, peers, unreadCounts, sendMessage, formatUser } = useTuneCampChat({
    serverUrl: 'https://sudorecords.tunecamp.net',
    token: 'USER_JWT_TOKEN'
  }, activePeerUsername);

  return (
    <div>
      {messages.map((m, i) => (
        <div key={i}>
          <strong>{formatUser(m.from, m.instance)}</strong>: {m.text}
        </div>
      ))}
      <button onClick={() => sendMessage(activePeerUsername, 'Hello!')}>Send</button>
    </div>
  );
}
```

### Pure TypeScript / Node / Framework Agnostic (`TuneCampChatClient`)

```typescript
import { TuneCampChatClient, formatUsernameWithInstance } from '@tunecamp/chat';

const client = new TuneCampChatClient('https://sudorecords.tunecamp.net', 'TOKEN');

client.onMessage((msg) => {
  const formattedUser = formatUsernameWithInstance(msg.from, msg.instance);
  console.log(`[${formattedUser}] ${msg.text}`);
});

client.connect();
client.sendMessage('', 'Hello Lobby!');
```

---

## 📄 License

MIT © TuneCamp
