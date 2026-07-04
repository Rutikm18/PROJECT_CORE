import { useState, useRef, useEffect, type FormEvent } from "react";
import { Eye, EyeOff, Shield, AlertCircle, Loader2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";

interface LoginPageProps {
  onSuccess: () => void;
}

export default function LoginPage({ onSuccess }: LoginPageProps) {
  const { login } = useAuth();

  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw]   = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [locked,   setLocked]   = useState(false);
  const [notice,   setNotice]   = useState<string | null>(null);

  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
    try {
      const reason = sessionStorage.getItem("al_logout_reason");
      if (reason === "idle") setNotice("You were signed out due to inactivity.");
    } catch { /* ignore */ }
  }, []);

  // Basic client-side validation — catches obvious mistakes before hitting the API
  function validate(): string | null {
    const e = email.trim();
    const p = password.trim();
    if (!e) return "Email is required.";
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e)) return "Enter a valid email address.";
    if (!p) return "Password is required.";
    if (p.length < 6) return "Password is too short.";
    return null;
  }

  async function handleSubmit(evt: FormEvent) {
    evt.preventDefault();
    if (loading || locked) return;

    setError(null);
    const validationError = validate();
    if (validationError) { setError(validationError); return; }

    setLoading(true);
    const result = await login(email.trim(), password.trim());
    setLoading(false);

    if (result.ok) {
      onSuccess();
    } else {
      const msg = result.error ?? "Login failed.";
      setError(msg);
      if (msg.toLowerCase().includes("too many")) {
        setLocked(true);
        // Allow retry after 15 min (matches server lockout)
        setTimeout(() => setLocked(false), 15 * 60 * 1000);
      }
      // Never leak which field was wrong — clear only password on failure
      setPassword("");
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{
        background: "linear-gradient(135deg, #0a0e1a 0%, #0f1829 40%, #111d35 100%)",
      }}
    >
      {/* Background grid texture */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: "linear-gradient(rgba(255,255,255,.7) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.7) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative w-full max-w-[400px] mx-4">
        {/* Logo / brand */}
        <div className="text-center mb-8">
          <div
            className="inline-flex items-center justify-center w-14 h-14 rounded-2xl mb-4"
            style={{ background: "linear-gradient(135deg, #f97316, #dc2626)" }}
          >
            <Shield className="w-7 h-7 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AttackLens</h1>
          <p className="text-sm mt-1" style={{ color: "rgba(255,255,255,0.4)" }}>
            Security Operations Platform
          </p>
        </div>

        {/* Card */}
        <div
          className="rounded-2xl p-8"
          style={{
            background: "rgba(255,255,255,0.04)",
            border: "1px solid rgba(255,255,255,0.09)",
            boxShadow: "0 24px 64px rgba(0,0,0,0.5)",
            backdropFilter: "blur(20px)",
          }}
        >
          <h2 className="text-base font-semibold text-white mb-1">Sign in to your account</h2>
          <p className="text-xs mb-6" style={{ color: "rgba(255,255,255,0.35)" }}>
            Use your organization credentials to access the dashboard.
          </p>

          <form onSubmit={handleSubmit} noValidate>
            {/* Email */}
            <div className="mb-4">
              <label
                htmlFor="al-email"
                className="block text-xs font-medium mb-1.5"
                style={{ color: "rgba(255,255,255,0.6)" }}
              >
                Email address
              </label>
              <input
                id="al-email"
                ref={emailRef}
                type="email"
                autoComplete="username email"
                value={email}
                onChange={e => { setEmail(e.target.value); setError(null); }}
                disabled={loading || locked}
                placeholder="you@attacklens.ai"
                className="w-full rounded-lg px-3.5 py-2.5 text-sm text-white placeholder-[rgba(255,255,255,0.2)] outline-none transition-all"
                style={{
                  background: "rgba(255,255,255,0.06)",
                  border: `1px solid ${error ? "rgba(239,68,68,0.5)" : "rgba(255,255,255,0.1)"}`,
                }}
                onFocus={e => (e.currentTarget.style.borderColor = "rgba(249,115,22,0.6)")}
                onBlur={e => (e.currentTarget.style.borderColor = error ? "rgba(239,68,68,0.5)" : "rgba(255,255,255,0.1)")}
              />
            </div>

            {/* Password */}
            <div className="mb-5">
              <label
                htmlFor="al-password"
                className="block text-xs font-medium mb-1.5"
                style={{ color: "rgba(255,255,255,0.6)" }}
              >
                Password
              </label>
              <div className="relative">
                <input
                  id="al-password"
                  type={showPw ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={e => { setPassword(e.target.value); setError(null); }}
                  disabled={loading || locked}
                  placeholder="••••••••••••"
                  className="w-full rounded-lg px-3.5 py-2.5 pr-10 text-sm text-white placeholder-[rgba(255,255,255,0.2)] outline-none transition-all"
                  style={{
                    background: "rgba(255,255,255,0.06)",
                    border: `1px solid ${error ? "rgba(239,68,68,0.5)" : "rgba(255,255,255,0.1)"}`,
                  }}
                  onFocus={e => (e.currentTarget.style.borderColor = "rgba(249,115,22,0.6)")}
                  onBlur={e => (e.currentTarget.style.borderColor = error ? "rgba(239,68,68,0.5)" : "rgba(255,255,255,0.1)")}
                />
                <button
                  type="button"
                  onClick={() => setShowPw(v => !v)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 transition-opacity hover:opacity-80"
                  style={{ color: "rgba(255,255,255,0.35)" }}
                  tabIndex={-1}
                  aria-label={showPw ? "Hide password" : "Show password"}
                >
                  {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            {/* Idle/expiry notice */}
            {notice && !error && (
              <div
                className="flex items-start gap-2.5 rounded-lg px-3.5 py-2.5 mb-5 text-xs"
                style={{ background: "rgba(251,191,36,0.1)", border: "1px solid rgba(251,191,36,0.25)", color: "#fcd34d" }}
                role="status"
              >
                <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                <span>{notice}</span>
              </div>
            )}

            {/* Error banner */}
            {error && (
              <div
                className="flex items-start gap-2.5 rounded-lg px-3.5 py-2.5 mb-5 text-xs"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.25)", color: "#fca5a5" }}
                role="alert"
                aria-live="assertive"
              >
                <AlertCircle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || locked}
              className="w-full flex items-center justify-center gap-2 rounded-lg py-2.5 text-sm font-semibold text-white transition-all"
              style={{
                background: loading || locked
                  ? "rgba(249,115,22,0.4)"
                  : "linear-gradient(135deg, #f97316, #ea580c)",
                cursor: loading || locked ? "not-allowed" : "pointer",
                boxShadow: loading || locked ? "none" : "0 4px 16px rgba(249,115,22,0.3)",
              }}
            >
              {loading
                ? <><Loader2 className="w-4 h-4 animate-spin" /> Signing in…</>
                : locked
                  ? "Account locked — try again later"
                  : "Sign in"}
            </button>
          </form>
        </div>

        {/* Dev credentials hint */}
        <div
          className="rounded-xl px-4 py-3 mt-4 cursor-pointer select-none"
          style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}
          onClick={() => { setEmail("admin@attacklens.ai"); setPassword("!HLwS=f73fHo$?p!#M77XA*M"); setError(null); }}
          title="Click to fill credentials"
        >
          <p className="text-[10px] font-semibold mb-1.5" style={{ color: "rgba(255,255,255,0.3)" }}>
            DEFAULT CREDENTIALS · CLICK TO FILL
          </p>
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <span className="text-[10px] w-14" style={{ color: "rgba(255,255,255,0.25)" }}>Email</span>
              <span className="text-[11px] font-mono" style={{ color: "rgba(255,255,255,0.55)" }}>admin@attacklens.ai</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] w-14" style={{ color: "rgba(255,255,255,0.25)" }}>Password</span>
              <span className="text-[11px] font-mono" style={{ color: "rgba(255,255,255,0.55)" }}>!HLwS=f73fHo$?p!#M77XA*M</span>
            </div>
          </div>
        </div>

        <p className="text-center text-[10px] mt-4" style={{ color: "rgba(255,255,255,0.15)" }}>
          AttackLens · Secure access only · All activity is logged
        </p>
      </div>
    </div>
  );
}
