import { useState, useRef, useEffect, type FormEvent } from "react";
import { Eye, EyeOff, AlertCircle, Loader2 } from "lucide-react";
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
          {/* AttackLens Logo */}
          <img 
            src="/logo-icon.svg" 
            alt="AttackLens" 
            className="w-16 h-16 mx-auto mb-4 drop-shadow-lg"
          />
          <h1 className="text-2xl font-bold text-white tracking-tight">AttackLens</h1>
          <p className="text-sm mt-1" style={{ color: "rgba(255,255,255,0.4)" }}>
            Security Operations Platform
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
          <p>Default: admin@attacklens.ai</p>
          <p className="mt-1">Password shown on first login screen</p>
        </div>
      </div>
    </div>
  );
}
