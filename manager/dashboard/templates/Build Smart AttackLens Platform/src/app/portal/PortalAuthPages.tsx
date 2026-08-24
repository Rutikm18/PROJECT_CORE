/**
 * PortalAuthPages — customer login and invite redemption.
 *
 * Separate from the operator login by design: a different cookie, different
 * lockout counters, and a different principal. Sharing the page would make it
 * far too easy to end up sharing the session too.
 *
 * The login surfaces one error for every failure — the server returns the same
 * answer for an unknown email, a wrong password, and a suspended org, and the
 * UI must not helpfully distinguish them.
 */
import { useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { AlertTriangle, CheckCircle2, Loader2, ShieldCheck } from "lucide-react";
import { cn } from "../../lib/utils";
import { PORTAL_API } from "./portalClient";

const inputCls = "w-full px-3 py-2.5 text-[13px] border border-[--gray-200] rounded-xl bg-white focus:outline-none focus:ring-2 focus:ring-purple-200 focus:border-purple-300 transition-all placeholder:text-[--gray-300]";

function AuthFrame({ title, subtitle, children }: {
  title: string; subtitle: string; children: React.ReactNode;
}) {
  return (
    <div className="min-h-screen bg-[--gray-50] flex items-center justify-center p-5">
      <div className="w-full max-w-[380px]">
        <div className="flex flex-col items-center mb-6">
          <div className="w-12 h-12 rounded-2xl flex items-center justify-center mb-3"
            style={{
              background: "linear-gradient(135deg,rgba(124,58,237,0.1),rgba(139,92,246,0.15))",
              border: "1px solid rgba(124,58,237,0.2)",
            }}>
            <ShieldCheck className="w-6 h-6" style={{ color: "#7C3AED" }} />
          </div>
          <h1 className="text-[17px] font-bold text-[--gray-900]">{title}</h1>
          <p className="text-[11px] text-[--gray-500] mt-1 text-center">{subtitle}</p>
        </div>
        <div className="bg-white border border-[--gray-200] rounded-2xl shadow-card overflow-hidden">
          <div className="h-[3px]" style={{ background: "linear-gradient(90deg,#7C3AED,#8B5CF6,#A78BFA)" }} />
          <div className="p-5 space-y-4">{children}</div>
        </div>
      </div>
    </div>
  );
}

function ErrorNote({ message }: { message: string }) {
  return (
    <div className="flex items-start gap-2 px-3 py-2 bg-red-50 border border-red-200 rounded-xl">
      <AlertTriangle className="w-3.5 h-3.5 text-red-600 flex-shrink-0 mt-0.5" />
      <span className="text-[11px] text-red-800">{message}</span>
    </div>
  );
}

// ── Login ───────────────────────────────────────────────────────────────────

export function PortalLogin() {
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(null);
    try {
      const response = await fetch(`${PORTAL_API}/auth/login`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: email.trim(), password }),
      });
      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        // 429 is the one distinction worth drawing — it tells the customer to
        // wait rather than keep guessing. Everything else is one message.
        setError(
          response.status === 429
            ? "Too many attempts. Try again in a few minutes."
            : (body.error ?? "Invalid email or password."),
        );
        return;
      }
      navigate("/portal", { replace: true });
    } catch {
      setError("Could not reach the server. Check your connection and try again.");
    } finally { setBusy(false); }
  };

  return (
    <AuthFrame title="Security Portal" subtitle="Sign in to view your organisation's security posture">
      <form onSubmit={submit} className="space-y-3.5">
        {error && <ErrorNote message={error} />}
        <div>
          <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Email</label>
          <input className={inputCls} type="email" autoComplete="username" required
            value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" />
        </div>
        <div>
          <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Password</label>
          <input className={inputCls} type="password" autoComplete="current-password" required
            value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••••••" />
        </div>
        <button type="submit" disabled={busy || !email || !password}
          className={cn(
            "w-full flex items-center justify-center gap-2 px-4 py-2.5 text-white text-[12px] font-bold rounded-xl transition-colors",
            busy ? "bg-purple-300" : "bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300",
          )}>
          {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="text-[10px] text-[--gray-400] text-center leading-relaxed">
          Access is provided by your security provider. Contact them to add users
          or reset a password.
        </p>
      </form>
    </AuthFrame>
  );
}

// ── Invite redemption ───────────────────────────────────────────────────────

export function PortalAcceptInvite() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const token = params.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const [busy, setBusy] = useState(false);

  const mismatch = confirm.length > 0 && password !== confirm;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (mismatch) return;
    setBusy(true); setError(null);
    try {
      const response = await fetch(`${PORTAL_API}/auth/accept-invite`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        setError(typeof body.detail === "string" ? body.detail : "Could not set your password.");
        return;
      }
      setDone(true);
      setTimeout(() => navigate("/portal/login", { replace: true }), 1800);
    } catch {
      setError("Could not reach the server. Check your connection and try again.");
    } finally { setBusy(false); }
  };

  if (!token) {
    return (
      <AuthFrame title="Set up your account" subtitle="This link is incomplete">
        <ErrorNote message="This setup link is missing its token. Ask your security provider to send a new one." />
      </AuthFrame>
    );
  }

  if (done) {
    return (
      <AuthFrame title="You're all set" subtitle="Taking you to sign in…">
        <div className="flex items-center gap-2 px-3 py-2.5 bg-emerald-50 border border-emerald-200 rounded-xl">
          <CheckCircle2 className="w-4 h-4 text-emerald-600 flex-shrink-0" />
          <span className="text-[11px] text-emerald-900 font-semibold">
            Password set. Sign in with your email and new password.
          </span>
        </div>
      </AuthFrame>
    );
  }

  return (
    <AuthFrame title="Set up your account" subtitle="Choose a password for your security portal">
      <form onSubmit={submit} className="space-y-3.5">
        {error && <ErrorNote message={error} />}
        <div>
          <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">New password</label>
          <input className={inputCls} type="password" autoComplete="new-password" required
            value={password} onChange={e => setPassword(e.target.value)} placeholder="At least 16 characters" />
          <p className="text-[9px] text-[--gray-400] mt-1.5 leading-relaxed">
            At least 16 characters, with upper and lower case, a digit, and a symbol.
          </p>
        </div>
        <div>
          <label className="block text-[11px] font-semibold text-[--gray-700] mb-1.5">Confirm password</label>
          <input className={cn(inputCls, mismatch && "border-red-300 focus:ring-red-200")}
            type="password" autoComplete="new-password" required
            value={confirm} onChange={e => setConfirm(e.target.value)} placeholder="Type it again" />
          {mismatch && <p className="text-[10px] text-red-600 mt-1.5">Passwords do not match.</p>}
        </div>
        <button type="submit" disabled={busy || !password || mismatch}
          className="w-full flex items-center justify-center gap-2 px-4 py-2.5 bg-purple-600 hover:bg-purple-700 disabled:bg-purple-300 text-white text-[12px] font-bold rounded-xl transition-colors">
          {busy && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
          {busy ? "Setting password…" : "Set password"}
        </button>
        <p className="text-[10px] text-[--gray-400] text-center leading-relaxed">
          This link works once and expires. If it fails, ask for a new one.
        </p>
      </form>
    </AuthFrame>
  );
}
