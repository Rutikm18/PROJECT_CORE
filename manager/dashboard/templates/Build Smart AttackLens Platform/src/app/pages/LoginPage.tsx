import { useState, useRef, useEffect, type FormEvent } from "react";
import { useNavigate, useLocation } from "react-router";
import { Eye, EyeOff, AlertCircle, Loader2, KeyRound, Copy, Check, Wand2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";

interface LoginPageProps {
  onSuccess: () => void;
}

interface DefaultCreds {
  active:   boolean;
  email:    string | null;
  password: string | null;
}

export default function LoginPage({ onSuccess }: LoginPageProps) {
  const { login, isAuthenticated } = useAuth();
  const navigate  = useNavigate();
  const location  = useLocation();
  // Redirect to the page the user tried to visit before being sent to /login,
  // or fall back to /dashboard if they navigated here directly.
  const from = (location.state as { from?: Location } | null)?.from?.pathname ?? "/dashboard";

  // Already logged in — bounce straight to the app (handles browser-back after login)
  useEffect(() => {
    if (isAuthenticated) navigate(from, { replace: true });
  }, [isAuthenticated, navigate, from]);

  const [email,    setEmail]    = useState("");
  const [password, setPassword] = useState("");
  const [showPw,   setShowPw]   = useState(false);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [locked,   setLocked]   = useState(false);
  const [notice,   setNotice]   = useState<string | null>(null);

  const [defaultCreds, setDefaultCreds] = useState<DefaultCreds | null>(null);
  const [copied,       setCopied]       = useState(false);

  const emailRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    emailRef.current?.focus();
    try {
      const reason = sessionStorage.getItem("al_logout_reason");
      if (reason === "idle") setNotice("You were signed out due to inactivity.");
    } catch { /* ignore */ }

    // Fetch the default bootstrap credential — the backend only returns the
    // password while the built-in default is still in use (first-run setup).
    (async () => {
      try {
        const r = await fetch("/api/v1/auth/policy");
        if (!r.ok) return;
        const p = await r.json();
        if (p?.default_credentials?.active) setDefaultCreds(p.default_credentials);
      } catch { /* ignore — feature simply won't show */ }
    })();
  }, []);

  // Fill both fields with the default credential
  function autofillDefault() {
    if (!defaultCreds?.active) return;
    setEmail(defaultCreds.email ?? "");
    setPassword(defaultCreds.password ?? "");
    setShowPw(true);
    setError(null);
  }

  async function copyPassword() {
    if (!defaultCreds?.password) return;
    try {
      await navigator.clipboard.writeText(defaultCreds.password);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch { /* clipboard blocked — user can still read/type it */ }
  }

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
      onSuccess(); // backward-compat hook (no-op in new router)
      navigate(from, { replace: true });
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
          {/* AttackLens Logo */}
          <img
            src="/static/logo-icon.svg"
            alt="AttackLens"
            className="w-16 h-16 mx-auto mb-4 drop-shadow-lg"
          />
          <h1 className="text-2xl font-bold text-white tracking-tight">AttackLens</h1>
          <p className="text-sm mt-1" style={{ color: "rgba(255,255,255,0.4)" }}>
            Agentic Exposure Management Platform
          </p>
        </div>

        {/* Card */}
        <div
          className="rounded-3xl shadow-2xl overflow-hidden"
          style={{
            background: "linear-gradient(135deg, rgba(255,255,255,0.95) 0%, rgba(248,247,255,0.95) 100%)",
            backdropFilter: "blur(10px)",
          }}
        >
          <div className="p-8">
            {/* Infobox if session expired */}
            {notice && (
              <div className="mb-5 p-3 rounded-xl bg-amber-50 border border-amber-200 flex gap-2">
                <AlertCircle className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
                <span className="text-sm text-amber-800">{notice}</span>
              </div>
            )}

            {/* First-run default credentials — shown only while the built-in
                default password is still active (backend gates this). */}
            {defaultCreds?.active && (
              <div className="mb-5 p-3.5 rounded-xl bg-indigo-50 border border-indigo-200">
                <div className="flex items-center gap-1.5 mb-2">
                  <KeyRound className="w-4 h-4 text-indigo-600" />
                  <span className="text-xs font-bold text-indigo-800">First-time sign in</span>
                  <span className="ml-auto text-[9px] font-semibold text-indigo-500 uppercase tracking-wider">Default credentials</span>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="text-indigo-500 font-medium">Email</span>
                    <code className="font-mono text-indigo-900 select-all">{defaultCreds.email}</code>
                  </div>
                  <div className="flex items-center justify-between gap-2 text-[11px]">
                    <span className="text-indigo-500 font-medium">Password</span>
                    <div className="flex items-center gap-1.5 min-w-0">
                      <code className="font-mono text-indigo-900 select-all truncate">{defaultCreds.password}</code>
                      <button
                        type="button"
                        onClick={copyPassword}
                        title="Copy password"
                        className="flex-shrink-0 p-1 rounded-md text-indigo-500 hover:text-indigo-700 hover:bg-indigo-100 transition"
                      >
                        {copied ? <Check className="w-3.5 h-3.5 text-emerald-600" /> : <Copy className="w-3.5 h-3.5" />}
                      </button>
                    </div>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={autofillDefault}
                  className="mt-2.5 w-full flex items-center justify-center gap-1.5 py-1.5 rounded-lg bg-indigo-600 text-white text-[11px] font-bold hover:bg-indigo-700 transition"
                >
                  <Wand2 className="w-3.5 h-3.5" />
                  Autofill &amp; sign in
                </button>
                <p className="mt-2 text-[9px] text-indigo-400 leading-tight">
                  Change this password after first login — this box disappears once a custom password is set.
                </p>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-4">
              {/* Email */}
              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1.5">Email Address</label>
                <input
                  ref={emailRef}
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  disabled={locked}
                  placeholder="admin@attacklens.ai"
                  className="w-full px-4 py-2.5 rounded-xl border border-gray-200 bg-white/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-purple-500/20 focus:border-purple-400 transition-all text-sm placeholder:text-gray-400"
                />
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs font-semibold text-gray-700 mb-1.5">Password</label>
                <div className="relative">
                  <input
                    type={showPw ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    disabled={locked}
                    placeholder="••••••••"
                    className="w-full px-4 py-2.5 rounded-xl border border-gray-200 bg-white/50 focus:bg-white focus:outline-none focus:ring-2 focus:ring-purple-500/20 focus:border-purple-400 transition-all text-sm placeholder:text-gray-400"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPw(!showPw)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 transition"
                  >
                    {showPw ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="p-3 rounded-xl bg-red-50 border border-red-200 flex gap-2">
                  <AlertCircle className="w-5 h-5 text-red-600 flex-shrink-0 mt-0.5" />
                  <span className="text-sm text-red-700">{error}</span>
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading || locked}
                className="w-full py-2.5 rounded-xl bg-gradient-to-r from-purple-600 to-purple-700 text-white font-semibold text-sm hover:from-purple-700 hover:to-purple-800 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
              >
                {loading && <Loader2 className="w-4 h-4 animate-spin" />}
                {loading ? "Signing in..." : "Sign in"}
              </button>
            </form>
          </div>
        </div>

        {/* Footer info */}
        <div className="mt-6 text-center text-xs" style={{ color: "rgba(255,255,255,0.5)" }}>
          {defaultCreds?.active ? (
            <p>First-run default credentials shown above — change after sign in.</p>
          ) : (
            <p>Authorized access only · AttackLens Security Operations</p>
          )}
        </div>
      </div>
    </div>
  );
}
