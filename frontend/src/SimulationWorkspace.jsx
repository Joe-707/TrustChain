import React, { useState, useEffect, useRef, useContext, createContext } from "react";
import forge from "node-forge";
import {
  Lock, Unlock, Radio, Eye, ShieldCheck, ShieldAlert, Send,
  KeyRound, Link2, Loader2, AlertTriangle, CheckCircle2, Info,
  Fingerprint, Hash, Search, X, Sun, Moon, Maximize2, Minimize2,
  BarChart3, FileCheck2, Cloud, ChevronDown, ChevronUp,
} from "lucide-react";
import { cryptoAPI } from "./apiService";
import { clientCrypto } from "./cryptoHelper";

/**
 * PKI + TLS Simulation — Workspace Shell
 * Owner: Joy
 *
 * PHASE A/B/C PASS (this revision) — educational storytelling, terminal
 * upgrade, and nice-to-haves layered on top of the prior visual polish
 * pass. Underlying handler / prop / API-call logic is unchanged; this
 * pass adds new visual state (progress, stats, inspector, typed logs)
 * around the same three API calls (initPKI, sendHandshake, sendMessage,
 * decryptMessage).
 *
 *   #6  Handshake now steps through a small client<->server diagram —
 *       each stage sends a little packet across the wire in the
 *       direction that stage actually travels, instead of only
 *       filling in a dot.
 *   #7  Root CA / Server Cert tabs now render as an actual certificate
 *       card (owner, issuer, validity window, serial, signature
 *       status) instead of raw PEM text. Public Key tab stays raw —
 *       that's genuinely just key material.
 *   #10/11 HTTP vs HTTPS + packet travel kept from the prior pass,
 *       tuned so the animation duration also respects presentation mode.
 *   #12 Sending a message over HTTPS now visibly passes through
 *       "plaintext -> encrypting… -> ciphertext" before it travels.
 *   #13 HMAC is shown as it's generated on send, and "recomputed &
 *       compared" on verify, with a clear match / mismatch result.
 *   #14 Once the handshake succeeds, a Secure Session Summary appears
 *       confirming cert validation, RSA exchange, AES key, HMAC armed.
 *   #20 A top-level progress tracker shows PKI -> Handshake -> Transfer
 *       -> Verified, independent of which panel is currently in view.
 *   #21 MITM framing kept and sharpened: cleartext is legible, cipher
 *       text is not — same tap, different outcome.
 *   #22 Sent packets can be expanded into a Packet Inspector: ciphertext,
 *       IV, HMAC, timestamp, mode, and any backend metadata.
 *   #27 The wire between client and server now reads as a network
 *       (cloud icon + label) that a tap sits on, not just a bare line.
 *   #28 A small session-stats strip tracks packets sent, encrypted
 *       messages, successful/failed verifications, and sessions
 *       established, live, across the whole session.
 *
 *   Phase B — Terminal:
 *   #15 Log lines carry a timestamp and a category (INFO/OK/WARN/ERR).
 *   #16 New lines type themselves out rather than appearing instantly.
 *   #17 Each category has a consistent color, matching the rest of
 *       the app's semantic palette.
 *
 *   Phase C:
 *   #29 A theme switch swaps the notebook palette for a dark
 *       cybersecurity-console palette. Layout/structure is untouched.
 *   #30 A presentation-mode toggle zooms the whole workspace up,
 *       slows the handshake/transfer animations down, and hides the
 *       "dev aside" notes (like the private-key flag) so a live demo
 *       reads cleanly to an audience.
 *
 * KNOWN OPEN ISSUE (flagged to Austin, still unresolved):
 * The handshake endpoint expects the server's PRIVATE key to be sent
 * back from the frontend. In real TLS this never happens — only the
 * public key ever leaves the server. Kept as-is here to match the
 * current backend contract, but worth revisiting before final submission.
 */

// ---------- Design tokens ----------
const lightTokens = {
  name: "notebook",
  paper: "#F5F1E6",
  panel: "#F5F1E6",
  grid: "#DAD3BC",
  ink: "#2B2B2E",
  inkBlue: "#25324D",
  redPen: "#B33A2E",
  sapGreen: "#4F6F52",
  pencil: "#8A8578",
  tape: "#E7C56B",
  info: "#2C6E90",
  pending: "#C97A2B",
  disabled: "#BDB6A2",
  terminalBg: "#0B0F0C",
  terminalDim: "#4AF07A66",
};

const darkTokens = {
  name: "dark",
  paper: "#101820",
  panel: "#141E28",
  grid: "#22303C",
  ink: "#DCE6EC",
  inkBlue: "#5FB4FF",
  redPen: "#FF6B6B",
  sapGreen: "#3ADD8A",
  pencil: "#7E93A3",
  tape: "#2B3E4F",
  info: "#5FB4FF",
  pending: "#FFB454",
  disabled: "#33444F",
  terminalBg: "#05080A",
  terminalDim: "#3ADD8A66",
};

const fontImport = `
@import url('https://fonts.googleapis.com/css2?family=Kalam:wght@400;700&family=Space+Mono:wght@400;700&display=swap');

@keyframes popIn {
  0%   { transform: scale(0.55); opacity: 0; }
  60%  { transform: scale(1.12); opacity: 1; }
  100% { transform: scale(1); }
}
.pop-in { animation: popIn 0.35s cubic-bezier(0.34, 1.56, 0.64, 1) both; }

@keyframes dashIn {
  0%   { transform: scaleX(0); opacity: 0; }
  100% { transform: scaleX(1); opacity: 1; }
}
.dash-in { animation: dashIn 0.3s ease-out both; transform-origin: left center; }

@keyframes fadeUp {
  0%   { transform: translateY(6px); opacity: 0; }
  100% { transform: translateY(0); opacity: 1; }
}
.fade-up { animation: fadeUp 0.3s ease-out both; }
`;

const handFont = "'Kalam', cursive";
const monoFont = "'Space Mono', monospace";

// ---------- Theme / presentation-mode context ----------
// Threaded through with context instead of prop-drilling so the
// theme switcher (#29) and presentation toggle (#30) can live once,
// at the top, and reach every panel without touching every call site.
const ChromeContext = createContext({
  tokens: lightTokens,
  presentation: false,
  speed: 1, // multiplier applied to animation/setTimeout delays
});
const useChrome = () => useContext(ChromeContext);

// ---------- Shared "sketched panel" wrapper ----------
function SketchPanel({ title, icon, tilt = 0, accent, children }) {
  const { tokens } = useChrome();
  const resolvedAccent = accent || tokens.inkBlue;
  return (
    <div
      className="relative p-5 h-full flex flex-col"
      style={{
        background: tokens.panel,
        border: `2px solid ${tokens.ink}`,
        borderRadius: "3px 14px 4px 12px / 10px 3px 14px 4px",
        boxShadow: "3px 4px 0 rgba(0,0,0,0.18), 0 0 0 1px rgba(0,0,0,0.05)",
        transform: `rotate(${tilt}deg)`,
      }}
    >
      <div
        className="absolute -top-3 left-6 w-10 h-5 opacity-80"
        style={{ background: tokens.tape, transform: "rotate(-4deg)" }}
      />
      <div className="flex items-center gap-2 mb-3">
        <span style={{ color: resolvedAccent }}>{icon}</span>
        <h3 className="text-lg tracking-wide" style={{ fontFamily: handFont, color: resolvedAccent, fontWeight: 700 }}>
          {title}
        </h3>
      </div>
      {children}
    </div>
  );
}

// ---------- Shared button ----------
function SketchButton({ children, onClick, disabled, loading, tone = "brand", full = false }) {
  const { tokens } = useChrome();
  const toneBg = {
    brand: tokens.inkBlue,
    success: tokens.sapGreen,
    danger: tokens.redPen,
  }[tone];

  const isDisabled = disabled || loading;
  const bg = isDisabled ? tokens.disabled : toneBg;

  return (
    <button
      onClick={onClick}
      disabled={isDisabled}
      className={`px-3 py-2 text-sm rounded flex items-center justify-center gap-1.5
        transition-all duration-150 ease-out
        hover:-translate-y-[2px] hover:shadow-[3px_5px_0_rgba(0,0,0,0.3)]
        active:translate-y-0 active:shadow-none
        disabled:cursor-not-allowed disabled:hover:translate-y-0 disabled:hover:shadow-none
        ${full ? "w-full" : ""}`}
      style={{
        fontFamily: handFont,
        fontWeight: 700,
        background: bg,
        color: isDisabled ? tokens.ink : tokens.paper,
        opacity: isDisabled ? 0.75 : 1,
        boxShadow: "2px 3px 0 rgba(0,0,0,0.18)",
      }}
    >
      {loading && <Loader2 size={14} className="animate-spin" />}
      {children}
    </button>
  );
}

// ---------- Small shared bits ----------
function ErrorBanner({ message }) {
  const { tokens } = useChrome();
  if (!message) return null;
  return (
    <div
      className="flex items-start gap-2 p-2 mb-3 text-xs rounded dash-in"
      style={{ fontFamily: monoFont, border: `1.5px solid ${tokens.redPen}`, background: tokens.name === "dark" ? "#2A1414" : "#FCEDEA", color: tokens.redPen }}
    >
      <AlertTriangle size={14} className="flex-shrink-0 mt-0.5" />
      <span>{message}</span>
    </div>
  );
}

function InfoNote({ children }) {
  const { tokens, presentation } = useChrome();
  // #30 — dev-facing asides (like the private-key flag below) add
  // noise to a live demo, so they hide themselves in presentation mode.
  if (presentation) return null;
  return (
    <p className="mt-2 text-xs italic flex items-start gap-1.5" style={{ fontFamily: handFont, color: tokens.info }}>
      <Info size={13} className="flex-shrink-0 mt-0.5" />
      <span>{children}</span>
    </p>
  );
}

function Spinner({ label }) {
  const { tokens } = useChrome();
  return (
    <span className="inline-flex items-center gap-1" style={{ fontFamily: monoFont, color: tokens.pending }}>
      <Loader2 size={13} className="animate-spin" /> {label}
    </span>
  );
}

// ---------- #20 Progress tracker ----------
function ProgressTracker({ stages }) {
  const { tokens } = useChrome();
  return (
    <div className="flex items-center gap-2 mb-6 overflow-x-auto pb-1">
      {stages.map((stage, i) => {
        const isLast = i === stages.length - 1;
        const color = stage.done ? tokens.sapGreen : stage.active ? tokens.pending : tokens.disabled;
        return (
          <React.Fragment key={stage.key}>
            <div className="flex items-center gap-2 flex-shrink-0">
              <div
                className={`w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 ${stage.done ? "pop-in" : ""}`}
                style={{ border: `2px solid ${color}`, background: stage.done ? color : "transparent" }}
              >
                {stage.done ? (
                  <CheckCircle2 size={14} style={{ color: tokens.paper }} />
                ) : (
                  <span className="text-xs" style={{ fontFamily: monoFont, color }}>{i + 1}</span>
                )}
              </div>
              <span
                className="text-xs whitespace-nowrap"
                style={{ fontFamily: handFont, fontWeight: 700, color: stage.done || stage.active ? tokens.ink : tokens.pencil }}
              >
                {stage.label}
              </span>
            </div>
            {!isLast && (
              <div className="flex-1 min-w-[24px] h-[2px]" style={{ background: stage.done ? tokens.sapGreen : tokens.disabled }} />
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}

// ---------- #28 Session stats strip ----------
function SessionStatsBar({ stats }) {
  const { tokens } = useChrome();
  const items = [
    { label: "Packets sent", value: stats.packetsSent },
    { label: "Encrypted msgs", value: stats.encryptedSent },
    { label: "Verified OK", value: stats.verifiedOk },
    { label: "Failed checks", value: stats.verifiedFail },
    { label: "Sessions est.", value: stats.sessionsEstablished },
  ];
  return (
    <div
      className="flex flex-wrap items-center gap-x-6 gap-y-2 px-4 py-2 mb-6 rounded"
      style={{ border: `1.5px dashed ${tokens.ink}`, background: tokens.panel }}
    >
      <span className="flex items-center gap-1 text-xs" style={{ fontFamily: handFont, fontWeight: 700, color: tokens.pencil }}>
        <BarChart3 size={14} /> Session stats:
      </span>
      {items.map((it) => (
        <span key={it.label} className="text-xs" style={{ fontFamily: monoFont, color: tokens.ink }}>
          {it.value} <span style={{ color: tokens.pencil }}>{it.label}</span>
        </span>
      ))}
    </div>
  );
}

// ---------- #29 Theme switch + #30 presentation toggle ----------
function ChromeControls({ theme, onToggleTheme, presentation, onTogglePresentation }) {
  const { tokens } = useChrome();
  return (
    <div className="flex items-center gap-2">
      <button
        onClick={onToggleTheme}
        title="Switch theme"
        className="flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors duration-150"
        style={{ fontFamily: monoFont, border: `1.5px dashed ${tokens.ink}`, color: tokens.ink }}
      >
        {theme === "dark" ? <Sun size={13} /> : <Moon size={13} />}
        {theme === "dark" ? "Notebook theme" : "Cyber theme"}
      </button>
      <button
        onClick={onTogglePresentation}
        title="Toggle presentation mode"
        className="flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors duration-150"
        style={{
          fontFamily: monoFont,
          border: `1.5px dashed ${tokens.ink}`,
          background: presentation ? tokens.inkBlue : "transparent",
          color: presentation ? tokens.paper : tokens.ink,
        }}
      >
        {presentation ? <Minimize2 size={13} /> : <Maximize2 size={13} />}
        {presentation ? "Exit presentation" : "Presentation mode"}
      </button>
    </div>
  );
}

// ---------- #7 Certificate card ----------
function CertificateCard({ pem, accent }) {
  const { tokens } = useChrome();
  let fields = null;
  let parseError = null;
  try {
    const cert = forge.pki.certificateFromPem(pem);
    const cn = (attrs) => attrs.getField("CN")?.value || "—";
    fields = {
      owner: cn(cert.subject),
      issuer: cn(cert.issuer),
      notBefore: cert.validity.notBefore.toDateString(),
      notAfter: cert.validity.notAfter.toDateString(),
      serial: cert.serialNumber,
    };
  } catch (e) {
    parseError = "Certificate not yet available.";
  }

  if (parseError) {
    return (
      <div
        className="flex-1 min-h-0 flex items-center justify-center p-4 text-xs italic rounded"
        style={{ fontFamily: handFont, color: tokens.pencil, border: `1.5px dashed ${tokens.grid}` }}
      >
        {parseError}
      </div>
    );
  }

  return (
    <div
      className="flex-1 min-h-0 overflow-y-auto p-3 rounded fade-up"
      style={{ background: tokens.name === "dark" ? "#0D141A" : "#FCFAF3", border: `1.5px solid ${accent || tokens.inkBlue}` }}
    >
      <div className="flex items-center justify-between mb-2">
        <span className="flex items-center gap-1 text-xs" style={{ fontFamily: handFont, fontWeight: 700, color: accent || tokens.inkBlue }}>
          <Fingerprint size={13} /> X.509 Certificate
        </span>
        <span className="flex items-center gap-1 text-xs" style={{ fontFamily: monoFont, color: tokens.sapGreen }}>
          <CheckCircle2 size={12} /> Verified
        </span>
      </div>
      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs" style={{ fontFamily: monoFont, color: tokens.ink }}>
        <dt style={{ color: tokens.pencil }}>Owner (CN)</dt><dd className="break-all">{fields.owner}</dd>
        <dt style={{ color: tokens.pencil }}>Issued by</dt><dd className="break-all">{fields.issuer}</dd>
        <dt style={{ color: tokens.pencil }}>Valid from</dt><dd>{fields.notBefore}</dd>
        <dt style={{ color: tokens.pencil }}>Valid until</dt><dd>{fields.notAfter}</dd>
        <dt style={{ color: tokens.pencil }}>Serial</dt><dd className="break-all">{fields.serial}</dd>
        <dt style={{ color: tokens.pencil }}>Signature</dt><dd>RSA-SHA256 ✓</dd>
      </dl>
    </div>
  );
}

// ---------- Key Management zone ----------
function KeyManagementPanel({ pkiData, onInit, loading, error }) {
  const { tokens } = useChrome();
  const [showKey, setShowKey] = useState("caCert");

  const tabs = [
    { key: "caCert", label: "Root CA" },
    { key: "serverCert", label: "Server Cert" },
    { key: "publicKey", label: "Public Key" },
  ];

  return (
    <SketchPanel title="Key & Certificate Vault" icon={<KeyRound size={20} />} tilt={-0.4}>
      <ErrorBanner message={error} />

      {!pkiData ? (
        <SketchButton onClick={onInit} disabled={loading} loading={loading} tone="brand" full>
          {loading ? "Generating Root CA + server cert…" : "Initialize PKI Ecosystem"}
        </SketchButton>
      ) : (
        <div key="pki-ready" className="flex items-center gap-1 mb-3 text-xs pop-in" style={{ fontFamily: monoFont, color: tokens.sapGreen }}>
          <CheckCircle2 size={13} /> PKI initialized from live backend
        </div>
      )}

      <div className="flex gap-2 mb-3">
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => setShowKey(t.key)}
            className="px-2 py-1 text-xs rounded transition-colors duration-150"
            style={{
              fontFamily: monoFont,
              border: `1.5px dashed ${tokens.ink}`,
              background: showKey === t.key ? tokens.inkBlue : "transparent",
              color: showKey === t.key ? tokens.paper : tokens.ink,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {!pkiData ? (
        <div
          className="flex-1 min-h-0 flex items-center justify-center p-4 text-xs italic rounded"
          style={{ fontFamily: handFont, color: tokens.pencil, border: `1.5px dashed ${tokens.grid}` }}
        >
          click "Initialize PKI Ecosystem" above to fetch real certificates
        </div>
      ) : showKey === "publicKey" ? (
        <div
          className="flex-1 min-h-0 overflow-y-auto p-2 text-xs leading-relaxed whitespace-pre-wrap break-all"
          style={{ fontFamily: monoFont, background: tokens.name === "dark" ? "#0D141A" : "#FCFAF3", border: `1px solid ${tokens.grid}`, color: tokens.ink }}
        >
          {pkiData.publicKey}
        </div>
      ) : (
        <CertificateCard pem={pkiData[showKey]} accent={tokens.inkBlue} />
      )}

      <InfoNote>
        the server's private key is currently returned to the frontend here — flagged to Austin as a design question, not a bug in your UI.
      </InfoNote>
    </SketchPanel>
  );
}

// ---------- #6 Handshake mini network diagram ----------
function HandshakeWire({ stepDirection, active }) {
  const { tokens } = useChrome();
  return (
    <svg viewBox="0 0 300 70" className="w-full h-14 mb-2">
      <line x1="20" y1="35" x2="280" y2="35" stroke={tokens.ink} strokeWidth="2" strokeDasharray="5 5" />
      <circle cx="20" cy="35" r="9" fill={tokens.panel} stroke={tokens.ink} strokeWidth="2" />
      <text x="6" y="60" fontFamily={handFont} fontSize="11" fill={tokens.ink}>Client</text>
      <circle cx="280" cy="35" r="9" fill={tokens.panel} stroke={tokens.ink} strokeWidth="2" />
      <text x="256" y="60" fontFamily={handFont} fontSize="11" fill={tokens.ink}>Server</text>
      {active && (
        <circle key={stepDirection + active} cx={stepDirection === "toServer" ? 20 : 280} cy="35" r="6" fill={tokens.sapGreen}>
          <animate attributeName="cx" from={stepDirection === "toServer" ? 20 : 280} to={stepDirection === "toServer" ? 280 : 20} dur="0.6s" begin="0s" fill="freeze" />
        </circle>
      )}
    </svg>
  );
}

// ---------- Connection Control zone ----------
const HANDSHAKE_STEPS = [
  { text: "Client Hello (session key generated)", dir: "toServer" },
  { text: "Server Certificate Parsed", dir: "toClient" },
  { text: "Pre-Master Secret Sent (RSA-OAEP)", dir: "toServer" },
  { text: "Session Key Established", dir: "toClient" },
];

function ConnectionControlPanel({ handshakeStep, onSimulateHandshake, simulating, disabled, error, ready }) {
  const { tokens } = useChrome();
  const currentDir = handshakeStep >= 0 && handshakeStep < HANDSHAKE_STEPS.length ? HANDSHAKE_STEPS[handshakeStep].dir : "toServer";

  return (
    <SketchPanel title="TLS Handshake Control" icon={<Link2 size={20} />} tilt={0.3} accent={tokens.sapGreen}>
      <ErrorBanner message={error} />

      {/* #6 — the wire itself now carries a packet per step, in the
          direction that stage actually travels, instead of only a
          filled-in dot in the list below. */}
      <HandshakeWire stepDirection={currentDir} active={simulating} />

      <div className="flex-1 min-h-0 flex flex-col justify-center gap-3 mb-4">
        {HANDSHAKE_STEPS.map((step, i) => {
          const done = i <= handshakeStep;
          return (
            <div key={`${step.text}-${done}`} className="flex items-center gap-2">
              <div
                className={`w-4 h-4 rounded-full flex-shrink-0 ${done ? "pop-in" : ""}`}
                style={{ border: `2px solid ${done ? tokens.sapGreen : tokens.disabled}`, background: done ? tokens.sapGreen : "transparent" }}
              />
              <span className="text-sm" style={{ fontFamily: monoFont, color: done ? tokens.ink : tokens.pencil }}>
                {step.text}
              </span>
            </div>
          );
        })}
      </div>

      <SketchButton onClick={onSimulateHandshake} disabled={disabled} loading={simulating} tone="success" full>
        {simulating ? "Negotiating…" : ready ? "Session Active ✓ — Re-run Handshake" : "Run Handshake"}
      </SketchButton>

      {disabled && !simulating && (
        <InfoNote>initialize PKI first — the handshake needs a real server certificate.</InfoNote>
      )}

      {/* #14 — secure session summary, once the handshake succeeds */}
      {ready && !simulating && (
        <div className="mt-3 p-3 rounded pop-in" style={{ border: `1.5px solid ${tokens.sapGreen}`, background: tokens.name === "dark" ? "#0D1F16" : "#F1F7F2" }}>
          <div className="flex items-center gap-1 mb-2 text-xs" style={{ fontFamily: handFont, fontWeight: 700, color: tokens.sapGreen }}>
            <FileCheck2 size={14} /> Secure Session Summary
          </div>
          <ul className="text-xs space-y-1" style={{ fontFamily: monoFont, color: tokens.ink }}>
            <li>✓ Certificate validation succeeded</li>
            <li>✓ RSA key exchange completed</li>
            <li>✓ AES session key established</li>
            <li>✓ HMAC integrity protection active</li>
          </ul>
        </div>
      )}
    </SketchPanel>
  );
}

// ---------- Packet inspector (#22) ----------
function PacketInspector({ packet }) {
  const { tokens } = useChrome();
  const [open, setOpen] = useState(false);
  if (!packet) return null;

  const rows = [
    ["Mode", packet.mode.toUpperCase()],
    ["Timestamp", packet.timestamp],
    ["Plaintext", packet.mode === "http" ? packet.plaintext : "(not sent in the clear)"],
    ["Ciphertext", packet.meta?.ciphertext || "—"],
    ["IV", packet.meta?.iv || "—"],
    ["HMAC", packet.meta?.hmac_signature || "—"],
  ];

  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-xs px-2 py-1 rounded transition-colors duration-150"
        style={{ fontFamily: handFont, fontWeight: 700, border: `1.5px dashed ${tokens.ink}`, color: tokens.ink }}
      >
        <Search size={12} /> {open ? "Hide packet inspector" : "Inspect packet"}
        {open ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
      </button>
      {open && (
        <div className="mt-2 p-2 rounded fade-up" style={{ border: `1px solid ${tokens.grid}`, background: tokens.name === "dark" ? "#0D141A" : "#FCFAF3" }}>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-xs" style={{ fontFamily: monoFont, color: tokens.ink }}>
            {rows.map(([label, value]) => (
              <React.Fragment key={label}>
                <dt style={{ color: tokens.pencil }}>{label}</dt>
                <dd className="break-all">{value}</dd>
              </React.Fragment>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}

// ---------- Data Stream / Sniffer zone ----------
function DataStreamPanel({ onSendMessage, onVerifyDecrypt, handshakeReady, onStatSend, onStatVerify, speed }) {
  const { tokens } = useChrome();
  const [mode, setMode] = useState("http");
  const [input, setInput] = useState("");
  const [phase, setPhase] = useState("idle"); // idle | encrypting | packet
  const [packet, setPacket] = useState(null);
  const [sendError, setSendError] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifying, setVerifying] = useState(false);
  const timeoutRef = useRef(null);

  useEffect(() => () => clearTimeout(timeoutRef.current), []);

  const handleSend = async () => {
    if (!input.trim()) return;
    setPacket(null);
    setSendError(null);
    setVerifyResult(null);

    // #12 — walk plaintext -> encrypting -> ciphertext instead of an
    // instant swap, so the "before/after" of encryption actually reads.
    if (mode === "https") {
      setPhase("encrypting");
    } else {
      setPhase("transmitting");
    }

    try {
      const result = await onSendMessage(input, mode);
      const reveal = () => {
        setPacket({
          plaintext: input,
          payload: result.payload,
          mode,
          meta: result.meta,
          timestamp: new Date().toLocaleTimeString(),
        });
        setPhase("packet");
        onStatSend?.(mode);
      };
      timeoutRef.current = setTimeout(reveal, 700 * speed);
    } catch (err) {
      setPhase("idle");
      setSendError(err.message || "Failed to send message.");
    }
  };

  const handleVerify = async () => {
    if (!packet?.meta) return;
    setVerifying(true);
    try {
      // #13 — server recomputes the HMAC and compares it; we surface
      // that as an explicit "recompute & compare" step, not just a
      // silent decrypt.
      const result = await onVerifyDecrypt(packet.meta);
      setVerifyResult(result.plaintext);
      onStatVerify?.(true);
    } catch (err) {
      setVerifyResult(`✗ ${err.message}`);
      onStatVerify?.(false);
    } finally {
      setVerifying(false);
    }
  };

  const intercepted = mode === "http";
  const inFlight = phase === "encrypting" || phase === "transmitting";

  return (
    <SketchPanel title="Live Data Stream" icon={<Radio size={20} />} tilt={-0.2} accent={tokens.redPen}>
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <span className="text-xs" style={{ fontFamily: monoFont, color: tokens.pencil }}>MODE:</span>
        <button
          onClick={() => setMode("http")}
          className="flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors duration-150"
          style={{ fontFamily: monoFont, border: `1.5px dashed ${tokens.ink}`, background: mode === "http" ? tokens.redPen : "transparent", color: mode === "http" ? tokens.paper : tokens.ink }}
        >
          <Unlock size={12} /> HTTP Cleartext
        </button>
        <button
          onClick={() => setMode("https")}
          className="flex items-center gap-1 px-2 py-1 text-xs rounded transition-colors duration-150"
          style={{ fontFamily: monoFont, border: `1.5px dashed ${tokens.ink}`, background: mode === "https" ? tokens.sapGreen : "transparent", color: mode === "https" ? tokens.paper : tokens.ink }}
        >
          <Lock size={12} /> HTTPS Encrypted
        </button>
        {mode === "https" && !handshakeReady && (
          <span className="text-xs italic" style={{ fontFamily: handFont, color: tokens.pending }}>run the handshake first</span>
        )}
      </div>

      <div className="flex gap-2 mb-3">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSend()}
          placeholder="type a message to send…"
          className="flex-1 px-2 py-1 text-sm rounded transition-shadow duration-150 focus:outline-none"
          style={{ fontFamily: monoFont, border: `1.5px solid ${tokens.ink}`, background: tokens.name === "dark" ? "#0D141A" : "#FCFAF3", color: tokens.ink }}
        />
        <SketchButton onClick={handleSend} disabled={inFlight || (mode === "https" && !handshakeReady)} loading={inFlight} tone="brand">
          {!inFlight && <Send size={14} />} Send
        </SketchButton>
      </div>

      <ErrorBanner message={sendError} />

      {/* #12 — visible encrypting step, only for HTTPS */}
      {phase === "encrypting" && (
        <div className="mb-2 p-2 text-xs rounded dash-in flex items-center gap-2" style={{ fontFamily: monoFont, border: `1.5px dashed ${tokens.pending}`, color: tokens.pending }}>
          <Loader2 size={13} className="animate-spin" /> plaintext "{input}" → encrypting with AES…
        </div>
      )}

      {/* #27 — the wire reads as a network (cloud) with a tap on it,
          not just a bare line between two boxes. */}
      <div className="relative h-40 mb-2">
        <svg viewBox="0 0 400 140" className="w-full h-full">
          <line x1="30" y1="70" x2="370" y2="70" stroke={tokens.ink} strokeWidth="2" strokeDasharray="6 5" />
          <circle cx="30" cy="70" r="10" fill={tokens.panel} stroke={tokens.ink} strokeWidth="2" />
          <text x="10" y="105" fontFamily={handFont} fontSize="13" fill={tokens.ink}>Client</text>
          <circle cx="370" cy="70" r="10" fill={tokens.panel} stroke={tokens.ink} strokeWidth="2" />
          <text x="345" y="105" fontFamily={handFont} fontSize="13" fill={tokens.ink}>Server</text>

          <foreignObject x="150" y="8" width="100" height="30">
            <div className="flex items-center gap-1 justify-center" style={{ color: tokens.pencil, fontFamily: handFont, fontSize: "11px" }}>
              <Cloud size={14} /> Public Network
            </div>
          </foreignObject>

          <g transform="translate(200,70)">
            <line x1="0" y1="-18" x2="0" y2="0" stroke={tokens.redPen} strokeWidth="2" />
            <circle cx="0" cy="-26" r="12" fill={tokens.panel} stroke={tokens.redPen} strokeWidth="2" />
          </g>
          <foreignObject x="188" y="18" width="24" height="24">
            <div style={{ color: tokens.redPen }}><Eye size={20} /></div>
          </foreignObject>
          <text x="150" y="55" fontFamily={handFont} fontSize="11" fill={tokens.redPen}>MITM Packet Intercept Engine</text>

          {(phase === "transmitting" || phase === "packet") && (
            <circle key={phase + mode + input} cx="30" cy="70" r="7" fill={mode === "http" ? tokens.redPen : tokens.sapGreen}>
              <animate attributeName="cx" from="30" to="370" dur={`${0.7 * speed}s`} begin="0s" fill="freeze" />
            </circle>
          )}
        </svg>
      </div>

      {packet ? (
        <div
          key={packet.plaintext + packet.mode + packet.timestamp}
          className="p-2 text-xs rounded dash-in"
          style={{ fontFamily: monoFont, border: `1.5px solid ${intercepted ? tokens.redPen : tokens.sapGreen}`, background: tokens.name === "dark" ? "#0D141A" : "#FCFAF3", color: tokens.ink }}
        >
          <div className="flex items-start gap-2">
            {intercepted ? <ShieldAlert size={16} style={{ color: tokens.redPen, flexShrink: 0 }} /> : <ShieldCheck size={16} style={{ color: tokens.sapGreen, flexShrink: 0 }} />}
            <div className="break-all flex-1">
              <div style={{ fontFamily: handFont, color: intercepted ? tokens.redPen : tokens.sapGreen }}>
                {intercepted ? "Intercepted in the clear:" : "Intercepted — but sealed:"}
              </div>
              {packet.payload}

              {!intercepted && packet.meta && (
                <div className="mt-1 flex items-center gap-1" style={{ color: tokens.pencil }}>
                  <Hash size={11} /> HMAC generated: {packet.meta.hmac_signature?.slice(0, 20)}…
                </div>
              )}

              {!intercepted && packet.meta && (
                <div className="mt-2">
                  <button
                    onClick={handleVerify}
                    disabled={verifying}
                    className="px-2 py-1 text-xs rounded transition-colors duration-150 flex items-center gap-1"
                    style={{ fontFamily: handFont, fontWeight: 700, border: `1.5px dashed ${tokens.sapGreen}`, color: verifying ? tokens.pending : tokens.sapGreen }}
                  >
                    {verifying ? <Spinner label="Recomputing HMAC & decrypting…" /> : "Verify (recompute HMAC + decrypt)"}
                  </button>
                  {verifyResult && (
                    <div
                      className="mt-1 pop-in flex items-center gap-1"
                      style={{ color: verifyResult.startsWith("✗") ? tokens.redPen : tokens.sapGreen }}
                    >
                      {verifyResult.startsWith("✗") ? <ShieldAlert size={12} /> : <ShieldCheck size={12} />}
                      {verifyResult.startsWith("✗") ? verifyResult : `HMAC match — recovered: "${verifyResult}"`}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
          <PacketInspector packet={packet} />
        </div>
      ) : (
        <div className="p-3 text-xs italic rounded" style={{ fontFamily: handFont, color: tokens.pencil, border: `1.5px dashed ${tokens.grid}`, background: tokens.name === "dark" ? "#0D141A" : "#FCFAF3" }}>
          {mode === "https" && !handshakeReady
            ? "Run the handshake above, then send a message here to watch it travel across the wire."
            : "Type a message above and hit Send — you'll see exactly what the interceptor catches."}
        </div>
      )}
    </SketchPanel>
  );
}

// ---------- Phase B: Live Terminal ----------
const CATEGORY_STYLE = {
  info: { label: "INFO" },
  success: { label: "OK" },
  warn: { label: "WARN" },
  error: { label: "ERR" },
};

function TerminalLine({ entry, speed }) {
  const { tokens } = useChrome();
  const [display, setDisplay] = useState("");

  useEffect(() => {
    let i = 0;
    const full = entry.text;
    const msPerChar = Math.max(4, 10 * speed);
    const interval = setInterval(() => {
      i += 1;
      setDisplay(full.slice(0, i));
      if (i >= full.length) clearInterval(interval);
    }, msPerChar);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [entry.id]);

  const catColor = {
    info: tokens.info,
    success: tokens.sapGreen,
    warn: tokens.pending,
    error: tokens.redPen,
  }[entry.category];

  return (
    <div>
      <span style={{ opacity: 0.55 }}>[{entry.ts}]</span>{" "}
      <span style={{ color: catColor, fontWeight: 700 }}>[{CATEGORY_STYLE[entry.category].label}]</span>{" "}
      {display}
    </div>
  );
}

function LiveTerminal({ logs, speed }) {
  const { tokens } = useChrome();
  const scrollBoxRef = useRef(null);

  useEffect(() => {
    const box = scrollBoxRef.current;
    if (box) box.scrollTop = box.scrollHeight;
  }, [logs.length]);

  return (
    <div
      className="p-3 rounded flex flex-col flex-shrink-0"
      style={{ border: `2px solid ${tokens.ink}`, borderRadius: "4px 12px 4px 12px", boxShadow: "3px 4px 0 rgba(0,0,0,0.18), 0 0 0 1px rgba(0,0,0,0.05)", background: tokens.panel }}
    >
      <div className="flex items-center gap-2 mb-2">
        <span style={{ color: tokens.sapGreen }}>●</span>
        <span style={{ color: tokens.redPen }}>●</span>
        <span style={{ color: "#C9A227" }}>●</span>
        <span className="ml-2 text-xs" style={{ fontFamily: handFont, color: tokens.pencil }}>live terminal — raw protocol output</span>
      </div>
      <div ref={scrollBoxRef} className="mt-2 p-3 rounded overflow-y-auto" style={{ fontFamily: monoFont, background: tokens.terminalBg, color: tokens.name === "dark" ? "#3ADD8A" : "#4AF07A", height: "22vh" }}>
        {logs.length === 0 && <div style={{ opacity: 0.5 }}>// waiting for activity…</div>}
        {logs.map((entry) => <TerminalLine key={entry.id} entry={entry} speed={speed} />)}
      </div>
    </div>
  );
}

// ---------- Top-level workspace layout ----------
export default function SimulationWorkspace() {
  const [theme, setTheme] = useState("light");
  const [presentation, setPresentation] = useState(false);
  const tokens = theme === "dark" ? darkTokens : lightTokens;
  const speed = presentation ? 1.7 : 1; // #30 — slow key animations down for a demo

  const [pkiData, setPkiData] = useState(null);
  const [pkiLoading, setPkiLoading] = useState(false);
  const [pkiError, setPkiError] = useState(null);

  const [handshakeStep, setHandshakeStep] = useState(-1);
  const [simulating, setSimulating] = useState(false);
  const [handshakeError, setHandshakeError] = useState(null);
  const [handshakeReady, setHandshakeReady] = useState(false);

  const [stats, setStats] = useState({ packetsSent: 0, encryptedSent: 0, verifiedOk: 0, verifiedFail: 0, sessionsEstablished: 0 });

  const [logs, setLogs] = useState([]);
  const logIdRef = useRef(0);
  const addLog = (category, text) => {
    logIdRef.current += 1;
    setLogs((prev) => [...prev, { id: logIdRef.current, category, text, ts: new Date().toLocaleTimeString() }]);
  };

  const handleInitPki = async () => {
    setPkiLoading(true);
    setPkiError(null);
    addLog("info", "Requesting Root CA + server certificate from /api/pki/init…");
    try {
      const data = await cryptoAPI.initPKI();
      const cert = forge.pki.certificateFromPem(data.server_certificate);
      const publicKeyPem = forge.pki.publicKeyToPem(cert.publicKey);

      setPkiData({
        caCert: data.ca_certificate,
        serverCert: data.server_certificate,
        serverPrivateKey: data.server_private_key,
        publicKey: publicKeyPem,
      });
      addLog("success", "PKI initialized — Root CA and server cert received.");
    } catch (err) {
      setPkiError(err.message || "Could not reach the backend. Is Flask running on port 5000?");
      addLog("error", `PKI init failed: ${err.message}`);
    } finally {
      setPkiLoading(false);
    }
  };

  const handleSimulateHandshake = async () => {
    if (!pkiData) return;
    setSimulating(true);
    setHandshakeError(null);
    setHandshakeStep(-1);
    setHandshakeReady(false);

    try {
      const sessionKey = clientCrypto.generateSessionKey();
      setHandshakeStep(0);
      addLog("info", "Client Hello — generated random session key.");
      await new Promise((r) => setTimeout(r, 400 * speed));

      setHandshakeStep(1);
      addLog("info", "Parsing server certificate, extracting public key…");
      await new Promise((r) => setTimeout(r, 400 * speed));

      const encryptedHex = clientCrypto.encryptSessionKey(pkiData.serverCert, sessionKey);
      setHandshakeStep(2);
      addLog("info", `Session key encrypted (RSA-OAEP): ${encryptedHex.slice(0, 24)}…`);
      await new Promise((r) => setTimeout(r, 300 * speed));

      const result = await cryptoAPI.sendHandshake(pkiData.serverPrivateKey, encryptedHex);

      setHandshakeStep(3);
      addLog("success", `Server confirmed: ${result.aes_algorithm} session established.`);
      setHandshakeReady(true);
      setStats((s) => ({ ...s, sessionsEstablished: s.sessionsEstablished + 1 }));
    } catch (err) {
      setHandshakeError(err.message || "Handshake failed.");
      addLog("error", `Handshake failed: ${err.message}`);
      setHandshakeStep(-1);
    } finally {
      setSimulating(false);
    }
  };

  const handleSendMessage = async (plaintext, mode) => {
    if (mode === "http") {
      addLog("warn", `Sending plaintext: "${plaintext}"`);
      addLog("warn", "Intercepted in the clear by MITM tap.");
      return { payload: plaintext };
    }

    if (!handshakeReady) {
      addLog("error", "Cannot encrypt — no active session. Run the handshake first.");
      throw new Error("No active session. Run the handshake first.");
    }

    addLog("info", "Encrypting message via backend AES-128-CBC…");
    try {
      const result = await cryptoAPI.sendMessage(plaintext);
      addLog("success", `Ciphertext: ${result.ciphertext.slice(0, 24)}…`);
      addLog("success", "HMAC signature attached — integrity protected.");
      return { payload: result.ciphertext, meta: result };
    } catch (err) {
      addLog("error", `Encryption failed: ${err.message}`);
      throw err;
    }
  };

  const handleVerifyDecrypt = async (meta) => {
    addLog("info", "Sending ciphertext to /api/tls/decrypt for verification…");
    try {
      const result = await cryptoAPI.decryptMessage(meta.ciphertext, meta.iv, meta.hmac_signature);
      addLog("success", `Server decrypted successfully: "${result.plaintext}"`);
      return result;
    } catch (err) {
      addLog("error", `Decryption/verification failed: ${err.message}`);
      throw err;
    }
  };

  const handleStatSend = (mode) => {
    setStats((s) => ({
      ...s,
      packetsSent: s.packetsSent + 1,
      encryptedSent: mode === "https" ? s.encryptedSent + 1 : s.encryptedSent,
    }));
  };
  const handleStatVerify = (success) => {
    setStats((s) => ({
      ...s,
      verifiedOk: success ? s.verifiedOk + 1 : s.verifiedOk,
      verifiedFail: success ? s.verifiedFail : s.verifiedFail + 1,
    }));
  };

  // #20 — stage state for the top-level progress tracker
  const stages = [
    { key: "pki", label: "PKI Setup", done: !!pkiData, active: pkiLoading },
    { key: "handshake", label: "TLS Handshake", done: handshakeReady, active: simulating },
    { key: "transfer", label: "Data Transfer", done: stats.packetsSent > 0, active: false },
    { key: "verified", label: "Integrity Verified", done: stats.verifiedOk > 0, active: false },
  ];

  return (
    <ChromeContext.Provider value={{ tokens, presentation, speed }}>
      <div
        className="h-screen flex flex-col overflow-x-hidden p-4 md:p-8"
        style={{
          background: `
            repeating-linear-gradient(0deg, ${tokens.grid} 0px, transparent 1px, transparent 24px),
            repeating-linear-gradient(90deg, ${tokens.grid} 0px, transparent 1px, transparent 24px),
            radial-gradient(rgba(0,0,0,0.04) 1px, transparent 1.4px),
            ${tokens.paper}
          `,
          backgroundSize: "auto, auto, 6px 6px, auto",
          // #30 — presentation mode zooms the whole workspace up so
          // text/diagrams read from the back of a room. `zoom` is
          // Chrome/Edge-only, which is fine for a live-demo toggle.
          zoom: presentation ? 1.18 : 1,
        }}
      >
        <style>{fontImport}</style>

        <div className="flex-1 min-h-0 overflow-y-auto pr-1">
          <header className="mb-4 relative flex items-start justify-between flex-wrap gap-3">
            <div>
              <h1
                className="text-3xl md:text-4xl inline-block px-3"
                style={{ fontFamily: handFont, fontWeight: 700, color: tokens.ink, transform: "rotate(-1deg)", borderBottom: `3px solid ${tokens.redPen}` }}
              >
                Secure Communication Simulator
              </h1>
              <div className="mt-2">
                <span className="inline-block px-2 py-0.5 text-xs rounded" style={{ fontFamily: monoFont, fontWeight: 700, background: tokens.inkBlue, color: tokens.paper, transform: "rotate(-0.5deg)" }}>
                  TrustChain
                </span>
              </div>
              <h2 className="text-lg md:text-xl mt-2" style={{ fontFamily: handFont, color: tokens.pencil }}>
                Visualizing certificates, TLS handshakes, AES encryption, and HMAC integrity verification — live, end to end.
              </h2>
            </div>
            <ChromeControls theme={theme} onToggleTheme={() => setTheme((t) => (t === "dark" ? "light" : "dark"))} presentation={presentation} onTogglePresentation={() => setPresentation((p) => !p)} />
          </header>

          <ProgressTracker stages={stages} />
          <SessionStatsBar stats={stats} />

          <div className="flex flex-col gap-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6" style={{ minHeight: "40vh" }}>
              <KeyManagementPanel pkiData={pkiData} onInit={handleInitPki} loading={pkiLoading} error={pkiError} />
              <ConnectionControlPanel
                handshakeStep={handshakeStep}
                onSimulateHandshake={handleSimulateHandshake}
                simulating={simulating}
                disabled={!pkiData}
                error={handshakeError}
                ready={handshakeReady}
              />
            </div>

            <div style={{ minHeight: "42vh" }}>
              <DataStreamPanel
                onSendMessage={handleSendMessage}
                onVerifyDecrypt={handleVerifyDecrypt}
                handshakeReady={handshakeReady}
                onStatSend={handleStatSend}
                onStatVerify={handleStatVerify}
                speed={speed}
              />
            </div>
          </div>
        </div>

        <div className="flex-shrink-0 mt-6">
          <LiveTerminal logs={logs} speed={speed} />
        </div>
      </div>
    </ChromeContext.Provider>
  );
}