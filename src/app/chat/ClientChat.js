"use client";

import { useState, useEffect, useRef } from "react";
import { signOut } from "next-auth/react";
import { CryptoEngine } from "@/lib/crypto";

// ─── Stable REST API helpers (no Server Action IDs) ──────────────────────────
async function apiGetChats() {
  const res = await fetch("/api/chat/list");
  if (!res.ok) return [];
  return res.json();
}

async function apiGetMessages(chatId) {
  const res = await fetch(`/api/chat/messages?chatId=${chatId}`);
  if (!res.ok) throw new Error("Failed to fetch messages");
  return res.json();
}

async function apiSendMessage(chatId, content) {
  const res = await fetch("/api/chat/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chatId, content }),
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.error || "Send failed");
  }
  return res.json();
}

async function apiInitConnect(targetUsername) {
  const res = await fetch("/api/chat/list", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ targetUsername }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Connection failed");
  return data;
}
// ─────────────────────────────────────────────────────────────────────────────

export default function ClientChat({ initialChats, currentUser, encryptedPrivateKey }) {
  const [activeChatId, setActiveChatId] = useState(initialChats[0]?.id || null);
  const [messages, setMessages] = useState([]);
  const [chats, setChats] = useState(initialChats);
  const [targetUser, setTargetUser] = useState("");

  // E2EE States
  const [privKeys, setPrivKeys] = useState(null); // { privSig, privEnc }
  const [unlockError, setUnlockError] = useState("");
  const [activeSharedSecret, setActiveSharedSecret] = useState(null);

  const messagesEndRef = useRef(null);

  // Derive Shared Secret whenever active chat or keys change
  useEffect(() => {
    if (activeChatId && privKeys) {
      const chat = chats.find((c) => c.id === activeChatId);
      const peer = chat?.participants.find((p) => p.user.username !== currentUser)?.user;

      if (peer?.publicKey) {
        try {
          const parsedPub = JSON.parse(peer.publicKey);
          CryptoEngine.deriveSharedSecret(privKeys.privEnc, parsedPub.enc)
            .then((secret) => setActiveSharedSecret(secret))
            .catch(() => setActiveSharedSecret(null));
        } catch (e) {
          console.error("Failed to parse peer public key", e);
        }
      }
    } else {
      setActiveSharedSecret(null);
    }
  }, [activeChatId, privKeys, chats, currentUser]);

  // Polling + E2EE Decryption
  useEffect(() => {
    let interval;
    if (activeChatId && activeSharedSecret) {
      const fetchMsgs = async () => {
        try {
          const msgs = await apiGetMessages(activeChatId);
          const decryptedMsgs = await Promise.all(
            msgs.map(async (msg) => {
              try {
                const pubKeys = JSON.parse(
                  chats
                    .find((c) => c.id === activeChatId)
                    ?.participants.find((p) => p.user.username === msg.sender.username)
                    ?.user.publicKey
                );
                msg.content = await CryptoEngine.verifyAndDecryptMessage(
                  msg.content,
                  activeSharedSecret,
                  pubKeys.sig
                );
              } catch (decErr) {
                msg.content = `[CRYPTOGRAPHIC FAILURE: ${decErr.message}]`;
                msg.corrupted = true;
              }
              return msg;
            })
          );
          setMessages(decryptedMsgs);
        } catch (e) {
          console.error("Secure fetch failure", e);
        }
      };

      fetchMsgs();
      interval = setInterval(fetchMsgs, 3000);
    } else {
      setMessages([]);
    }
    return () => clearInterval(interval);
  }, [activeChatId, activeSharedSecret, chats, currentUser]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function handleUnlock(e) {
    e.preventDefault();
    setUnlockError("");
    const pass = e.target.password.value;
    try {
      const keys = await CryptoEngine.decryptPrivateKeysWithPassword(pass, encryptedPrivateKey);
      setPrivKeys(keys);
    } catch (err) {
      setUnlockError("Invalid key derivation. Password mismatch or corrupted sector.");
    }
  }

  async function handleSend(e) {
    e.preventDefault();
    const content = e.target.content.value;
    if (!content.trim() || !activeChatId || !activeSharedSecret || !privKeys) return;

    e.target.content.value = "";

    try {
      const encryptedPayload = await CryptoEngine.encryptAndSignMessage(
        content,
        activeSharedSecret,
        privKeys.privSig
      );
      const newMsgRaw = await apiSendMessage(activeChatId, encryptedPayload);
      setMessages((prev) => [...prev, { ...newMsgRaw, content }]);
    } catch (err) {
      alert("Encryption engine halt: " + err.message);
    }
  }

  async function handleNewConnection(e) {
    e.preventDefault();
    if (!targetUser) return;
    try {
      const newChat = await apiInitConnect(targetUser);
      if (!chats.find((c) => c.id === newChat.id)) {
        setChats((prev) => [newChat, ...prev]);
      }
      setActiveChatId(newChat.id);
      setTargetUser("");
    } catch (err) {
      alert(err.message);
    }
  }

  if (!privKeys) {
    return (
      <main style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", padding: "2rem" }}>
        <form onSubmit={handleUnlock} className="glass-panel" style={{ padding: "3rem", width: "100%", maxWidth: "450px", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          <h2 style={{ textAlign: "center", letterSpacing: "-1px", color: "var(--accent-cyan)" }}>NODE LOCKED</h2>
          <p style={{ textAlign: "center", fontSize: "0.875rem", color: "var(--text-secondary)" }}>
            Your private identity keys are encrypted locally. Input passphrase to decrypt keys into volatile memory.
          </p>
          {unlockError && (
            <div style={{ color: "#ff4d4d", fontSize: "0.875rem", border: "1px solid rgba(255, 77, 77, 0.3)", padding: "0.5rem", borderRadius: "4px", background: "rgba(255, 0, 0, 0.1)" }}>
              {unlockError}
            </div>
          )}
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            <label style={{ fontSize: "0.875rem", color: "var(--text-secondary)" }}>SECURE PASSPHRASE</label>
            <input type="password" name="password" required autoFocus />
          </div>
          <button type="submit" style={{ marginTop: "1rem" }}>DECRYPT IDENTITY</button>
          <button type="button" onClick={() => signOut()} style={{ background: "transparent", color: "#ff4d4d", border: "1px solid #ff4d4d" }}>
            TERMINATE SESSION
          </button>
        </form>
      </main>
    );
  }

  return (
    <div style={{ display: "flex", height: "100vh", width: "100vw", overflow: "hidden" }}>
      {/* Sidebar */}
      <div className="glass-panel" style={{ width: "300px", borderRight: "1px solid var(--glass-border)", display: "flex", flexDirection: "column", borderRadius: "0" }}>
        <div style={{ padding: "1.5rem", borderBottom: "1px solid var(--glass-border)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div>
            <div style={{ fontSize: "0.75rem", color: "var(--accent-cyan)", letterSpacing: "1px" }}>NODE AUTHENTICATED</div>
            <div style={{ fontWeight: "bold" }}>{currentUser}</div>
          </div>
          <button onClick={() => signOut()} style={{ padding: "8px", fontSize: "0.75rem", border: "1px solid #ff4d4d", color: "#ff4d4d", background: "transparent" }}>
            LOCK NODE
          </button>
        </div>

        <form onSubmit={handleNewConnection} style={{ padding: "1rem", display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--glass-border)" }}>
          <input type="text" placeholder="Target Node ID..." value={targetUser} onChange={(e) => setTargetUser(e.target.value)} style={{ flex: 1, padding: "8px" }} />
          <button type="submit" style={{ padding: "8px 12px" }}>CONNECT</button>
        </form>

        <div style={{ flex: 1, overflowY: "auto", padding: "1rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {chats.map((chat) => {
            const chatName = chat.name || chat.participants.filter((p) => p.user.username !== currentUser).map((p) => p.user.username).join(", ");
            return (
              <div
                key={chat.id}
                onClick={() => setActiveChatId(chat.id)}
                style={{
                  padding: "1rem",
                  cursor: "pointer",
                  background: activeChatId === chat.id ? "rgba(0, 229, 255, 0.15)" : "transparent",
                  border: "1px solid var(--glass-border)",
                  borderRadius: "4px",
                  transition: "all 0.2s",
                }}
              >
                {chatName || "Encrypted Channel"}
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Chat Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "rgba(0,0,0,0.2)" }}>
        {activeChatId ? (
          <>
            <div style={{ padding: "1.5rem", borderBottom: "1px solid var(--glass-border)", background: "rgba(4, 13, 20, 0.8)", backdropFilter: "blur(10px)" }}>
              <div style={{ fontSize: "0.875rem", color: "var(--accent-cyan)", display: "flex", justifyContent: "space-between" }}>
                <span>END-TO-END ENCRYPTED SESSION</span>
                {activeSharedSecret ? (
                  <span style={{ color: "#00e5ff" }}>[VERIFIED]</span>
                ) : (
                  <span style={{ color: "#ff4d4d" }}>[NEGOTIATING KEYS...]</span>
                )}
              </div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)" }}>ID: {activeChatId}</div>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "2rem", display: "flex", flexDirection: "column", gap: "1rem" }}>
              {messages.map((msg) => {
                const isMine = msg.sender?.username === currentUser;
                return (
                  <div key={msg.id} style={{ alignSelf: isMine ? "flex-end" : "flex-start", maxWidth: "70%", wordBreak: "break-word" }}>
                    {!isMine && (
                      <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginBottom: "4px", display: "flex", alignItems: "center", gap: "8px" }}>
                        {msg.sender?.username}
                        {!msg.corrupted && <span style={{ color: "#00e5ff" }}>✓ Sig Verified</span>}
                      </div>
                    )}
                    <div
                      className="glass-panel"
                      style={{
                        padding: "1rem",
                        borderRadius: "8px",
                        background: msg.corrupted ? "rgba(255,0,0,0.2)" : isMine ? "rgba(0, 229, 255, 0.1)" : "var(--glass-bg)",
                        border: msg.corrupted ? "1px solid red" : isMine ? "1px solid rgba(0, 229, 255, 0.3)" : "1px solid var(--glass-border)",
                      }}
                    >
                      {msg.content}
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            <div style={{ padding: "1.5rem", borderTop: "1px solid var(--glass-border)", background: "rgba(4, 13, 20, 0.8)", backdropFilter: "blur(10px)" }}>
              <form onSubmit={handleSend} style={{ display: "flex", gap: "1rem" }}>
                <button type="button" onClick={() => alert("Secure P2P Upload Bridge Offline")} style={{ padding: "12px", background: "transparent", border: "1px dashed var(--text-secondary)", color: "var(--text-secondary)" }}>
                  ATTACH
                </button>
                <input type="text" name="content" disabled={!activeSharedSecret} required placeholder="Transmit encrypted payload..." autoComplete="off" style={{ flex: 1 }} />
                <button type="submit" disabled={!activeSharedSecret} style={{ opacity: activeSharedSecret ? 1 : 0.5 }}>
                  TRANSMIT
                </button>
              </form>
            </div>
          </>
        ) : (
          <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)" }}>
            INITIALIZE CONNECTION NODE
          </div>
        )}
      </div>
    </div>
  );
}
