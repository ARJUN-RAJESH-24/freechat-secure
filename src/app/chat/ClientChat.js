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

async function apiSendMessage(chatId, content, type = "TEXT") {
  const res = await fetch("/api/chat/messages", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chatId, content, type }),
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

  const [privKeys, setPrivKeys] = useState(null); // { privSig, privEnc }
  const [unlockError, setUnlockError] = useState("");
  const [activeSharedSecret, setActiveSharedSecret] = useState(null);
  const [toast, setToast] = useState(null);
  const [isEncrypting, setIsEncrypting] = useState(false);
  const [showUnlockPassword, setShowUnlockPassword] = useState(false);

  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);
  const fileInputRef = useRef(null);

  const showToast = (msg, type = "error") => {
    setToast({ msg, type });
    setTimeout(() => setToast(null), 3000);
  };

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
    if (e && e.preventDefault) e.preventDefault();
    const content = inputRef.current?.value || "";
    if (!content.trim() || !activeChatId || !activeSharedSecret || !privKeys) return;

    if (inputRef.current) inputRef.current.value = "";

    try {
      // Look up the sender's own public key from the participants list for fingerprint binding
      const myParticipant = chats
        .find((c) => c.id === activeChatId)
        ?.participants.find((p) => p.user.username === currentUser);
      const mySigPubKey = myParticipant ? JSON.parse(myParticipant.user.publicKey).sig : null;

      const encryptedPayload = await CryptoEngine.encryptAndSignMessage(
        content,
        activeSharedSecret,
        privKeys.privSig,
        mySigPubKey   // sender pub key for fingerprint binding
      );

      const newMsgRaw = await apiSendMessage(activeChatId, encryptedPayload, "TEXT");
      setMessages((prev) => [...prev, { ...newMsgRaw, content, type: "TEXT" }]);
    } catch (err) {
      showToast("Encryption engine halt: " + err.message);
    }
  }

  const handleFileChange = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    
    // Clear the input so the same file can be selected again
    e.target.value = "";

    if (file.size > 2 * 1024 * 1024) {
      showToast("File too large. Maximum size for P2P encrypted bridge is 2MB.");
      return;
    }

    if (!activeChatId || !activeSharedSecret || !privKeys) {
      showToast("Secure connection not established.");
      return;
    }

    setIsEncrypting(true);
    try {
      // 1. Read file as Base64 Data URL
      const reader = new FileReader();
      reader.onload = async (event) => {
        try {
          const base64Content = event.target.result;
          
          const myParticipant = chats
            .find((c) => c.id === activeChatId)
            ?.participants.find((p) => p.user.username === currentUser);
          const mySigPubKey = myParticipant ? JSON.parse(myParticipant.user.publicKey).sig : null;

          // 2. Encrypt the Base64 string exactly like a text message
          const encryptedPayload = await CryptoEngine.encryptAndSignMessage(
            base64Content,
            activeSharedSecret,
            privKeys.privSig,
            mySigPubKey
          );

          // 3. Send the encrypted payload
          const newMsgRaw = await apiSendMessage(activeChatId, encryptedPayload, "IMAGE");
          setMessages((prev) => [...prev, { ...newMsgRaw, content: base64Content, type: "IMAGE" }]);
        } catch (err) {
          showToast("Attachment encryption failed: " + err.message);
        } finally {
          setIsEncrypting(false);
        }
      };
      reader.readAsDataURL(file);
    } catch (err) {
      showToast("File processing failed.");
      setIsEncrypting(false);
    }
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend(e);
    }
  };

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
      showToast(err.message);
    }
  }

  const formatTime = (isoString) => {
    if (!isoString) return "";
    return new Intl.DateTimeFormat("en-US", { hour: "numeric", minute: "numeric" }).format(new Date(isoString));
  };

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
            <div style={{ position: "relative", display: "flex", alignItems: "center" }}>
              <input type={showUnlockPassword ? "text" : "password"} name="password" required autoFocus style={{ width: "100%", paddingRight: "40px" }} />
              <button type="button" onClick={() => setShowUnlockPassword(!showUnlockPassword)} style={{ position: "absolute", right: "8px", background: "transparent", border: "none", padding: "4px", color: "var(--text-secondary)", cursor: "pointer", display: "flex" }}>
                {showUnlockPassword ? (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"></path></svg>
                ) : (
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                )}
              </button>
            </div>
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
          <button onClick={() => signOut()} style={{ padding: "8px", fontSize: "0.75rem", border: "1px solid #ff4d4d", color: "#ff4d4d", background: "transparent", whiteSpace: "nowrap", flexShrink: 0 }}>
            LOCK NODE
          </button>
        </div>

        <form onSubmit={handleNewConnection} style={{ padding: "1rem", display: "flex", gap: "0.5rem", borderBottom: "1px solid var(--glass-border)" }}>
          <input type="text" placeholder="Target Node ID..." value={targetUser} onChange={(e) => setTargetUser(e.target.value)} style={{ flex: 1, padding: "8px", minWidth: 0 }} />
          <button type="submit" style={{ padding: "8px 12px", flexShrink: 0, whiteSpace: "nowrap" }}>CONNECT</button>
        </form>

        <div style={{ flex: 1, overflowY: "auto", padding: "1rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {chats.map((chat) => {
            const chatName = chat.name || chat.participants.filter((p) => p.user.username !== currentUser).map((p) => p.user.username).join(", ");
            const initials = chatName.substring(0, 2).toUpperCase();
            const isActive = activeChatId === chat.id;
            
            return (
              <div
                key={chat.id}
                onClick={() => setActiveChatId(chat.id)}
                className="glass-panel"
                style={{
                  padding: "1rem",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "1rem",
                  background: isActive ? "rgba(0, 229, 255, 0.15)" : "var(--glass-bg)",
                  border: isActive ? "1px solid rgba(0, 229, 255, 0.4)" : "1px solid var(--glass-border)",
                  borderRadius: "8px",
                  transition: "all 0.2s",
                }}
              >
                <div style={{
                  width: "36px",
                  height: "36px",
                  borderRadius: "50%",
                  background: isActive ? "var(--accent-cyan)" : "rgba(0, 229, 255, 0.1)",
                  color: isActive ? "#000" : "var(--accent-cyan)",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  fontWeight: "bold",
                  fontSize: "0.875rem",
                  flexShrink: 0
                }}>
                  {initials}
                </div>
                <div style={{ fontWeight: isActive ? "600" : "400", whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
                  {chatName || "Encrypted Channel"}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Chat Area */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", background: "rgba(0,0,0,0.2)" }}>
        {activeChatId ? (
          <>
            <div style={{ padding: "1.5rem", borderBottom: "1px solid var(--glass-border)", background: "rgba(4, 13, 20, 0.8)", backdropFilter: "blur(10px)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div>
                <div style={{ fontSize: "0.875rem", color: "var(--accent-cyan)", display: "flex", alignItems: "center", gap: "8px" }}>
                  <span>E2EE SESSION</span>
                  {activeSharedSecret ? (
                    <span style={{ color: "#00e5ff", display: "flex", alignItems: "center", gap: "4px" }}>
                      <div style={{ width: "6px", height: "6px", background: "#00e5ff", borderRadius: "50%", boxShadow: "0 0 8px #00e5ff" }}></div>
                      VERIFIED
                    </span>
                  ) : (
                    <span style={{ color: "#ff4d4d", display: "flex", alignItems: "center", gap: "4px" }}>
                      <div style={{ width: "6px", height: "6px", background: "#ff4d4d", borderRadius: "50%", boxShadow: "0 0 8px #ff4d4d", animation: "pulse 1.5s infinite" }}></div>
                      NEGOTIATING KEYS...
                    </span>
                  )}
                </div>
                <div className="mono-text" style={{ fontSize: "0.75rem", color: "var(--text-secondary)", marginTop: "4px" }}>ID: {activeChatId}</div>
              </div>
            </div>

            <div style={{ flex: 1, overflowY: "auto", padding: "2rem", display: "flex", flexDirection: "column", gap: "1.5rem" }}>
              {messages.map((msg, index) => {
                const isMine = msg.sender?.username === currentUser;
                return (
                  <div key={msg.id} className="msg-enter" style={{ alignSelf: isMine ? "flex-end" : "flex-start", maxWidth: "75%", display: "flex", flexDirection: "column", gap: "4px", animationDelay: `${index * 0.05}s` }}>
                    {!isMine && (
                      <div style={{ fontSize: "0.75rem", color: "var(--text-secondary)", display: "flex", alignItems: "center", gap: "8px", paddingLeft: "4px" }}>
                        <span style={{ fontWeight: "600", color: "#fff" }}>{msg.sender?.username}</span>
                        <span>•</span>
                        <span>{formatTime(msg.createdAt)}</span>
                        {!msg.corrupted && <span style={{ color: "var(--accent-teal)", marginLeft: "auto" }}>✓ Sig Verified</span>}
                      </div>
                    )}
                    <div
                      className="glass-panel"
                      style={{
                        padding: msg.type === "IMAGE" && !msg.corrupted ? "0.5rem" : "1rem 1.25rem",
                        borderRadius: isMine ? "12px 12px 0 12px" : "12px 12px 12px 0",
                        background: msg.corrupted ? "rgba(255,0,0,0.2)" : isMine ? "rgba(0, 229, 255, 0.15)" : "var(--glass-bg)",
                        border: msg.corrupted ? "1px solid #ff4d4d" : isMine ? "1px solid rgba(0, 229, 255, 0.4)" : "1px solid var(--glass-border)",
                        boxShadow: isMine ? "0 4px 15px rgba(0, 229, 255, 0.1)" : "0 4px 15px rgba(0,0,0,0.2)",
                        whiteSpace: "pre-wrap",
                        lineHeight: "1.5"
                      }}
                    >
                      {msg.corrupted ? (
                        msg.content
                      ) : msg.type === "IMAGE" ? (
                        <img src={msg.content} alt="Encrypted Attachment" style={{ maxWidth: "100%", maxHeight: "300px", borderRadius: "8px", display: "block" }} />
                      ) : (
                        msg.content
                      )}
                    </div>
                    {isMine && (
                      <div style={{ fontSize: "0.7rem", color: "var(--text-secondary)", alignSelf: "flex-end", paddingRight: "4px" }}>
                        {formatTime(msg.createdAt)}
                      </div>
                    )}
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            <div style={{ padding: "1.5rem", borderTop: "1px solid var(--glass-border)", background: "rgba(4, 13, 20, 0.8)", backdropFilter: "blur(10px)" }}>
              <form onSubmit={handleSend} style={{ display: "flex", gap: "1rem", alignItems: "flex-end" }}>
                <input type="file" accept="image/*" ref={fileInputRef} onChange={handleFileChange} style={{ display: "none" }} />
                <button type="button" onClick={() => fileInputRef.current?.click()} disabled={!activeSharedSecret || isEncrypting} style={{ padding: "12px", background: "transparent", border: "1px dashed var(--text-secondary)", color: "var(--text-secondary)" }}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"></path></svg>
                </button>
                <textarea 
                  name="content" 
                  ref={inputRef}
                  onKeyDown={handleKeyDown}
                  disabled={!activeSharedSecret || isEncrypting} 
                  required 
                  placeholder={isEncrypting ? "Encrypting attachment..." : "Transmit encrypted payload... (Shift+Enter for new line)"} 
                  autoComplete="off" 
                  style={{ flex: 1, minHeight: "50px", maxHeight: "150px" }} 
                />
                <button type="submit" disabled={!activeSharedSecret || isEncrypting} style={{ opacity: activeSharedSecret && !isEncrypting ? 1 : 0.5, height: "50px" }}>
                  TRANSMIT
                </button>
              </form>
            </div>
          </>
        ) : (
          <div className="fade-in" style={{ flex: 1, display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", color: "var(--text-secondary)", gap: "1.5rem" }}>
            <div style={{ width: "80px", height: "80px", borderRadius: "50%", background: "rgba(0, 229, 255, 0.05)", display: "flex", alignItems: "center", justifyContent: "center", border: "1px dashed var(--accent-cyan)" }}>
               <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" strokeWidth="1" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path></svg>
            </div>
            <div style={{ letterSpacing: "2px", textTransform: "uppercase" }}>INITIALIZE CONNECTION NODE</div>
          </div>
        )}
      </div>

      {/* Toast Notification */}
      {toast && (
        <div className="fade-in glass-panel" style={{ position: "fixed", bottom: "2rem", right: "2rem", padding: "1rem 1.5rem", zIndex: 50, border: `1px solid ${toast.type === "error" ? "#ff4d4d" : "var(--accent-cyan)"}`, borderLeft: `4px solid ${toast.type === "error" ? "#ff4d4d" : "var(--accent-cyan)"}`, background: "rgba(4, 13, 20, 0.95)" }}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}
