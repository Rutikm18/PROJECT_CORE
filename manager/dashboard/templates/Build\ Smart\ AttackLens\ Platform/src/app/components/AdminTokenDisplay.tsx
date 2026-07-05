/**
 * AdminTokenDisplay — Display and copy ADMIN_TOKEN in Settings
 *
 * This component shows the admin API token (displayed at startup) with a copy button.
 * Users paste their token here for easy clipboard access.
 */

import { useState } from "react";
import { Copy, AlertCircle, Lock } from "lucide-react";

export function AdminTokenDisplay() {
  const [token, setToken] = useState("");
  const [masked, setMasked] = useState(true);
  const [copyFeedback, setCopyFeedback] = useState("");

  const handleCopy = async () => {
    if (!token.trim()) return;
    try {
      await navigator.clipboard.writeText(token.trim());
      setCopyFeedback("✓ Copied to clipboard");
      setTimeout(() => setCopyFeedback(""), 2000);
    } catch {
      setCopyFeedback("✗ Copy failed");
      setTimeout(() => setCopyFeedback(""), 2000);
    }
  };

  return (
    <div className="space-y-4">
      {/* Info box */}
      <div className="bg-blue-50 border border-blue-200 rounded-xl p-4 flex gap-3">
        <AlertCircle className="w-5 h-5 text-blue-600 flex-shrink-0 mt-0.5" />
        <div className="text-sm text-blue-800">
          <strong>ADMIN_TOKEN</strong> is displayed once at startup in the Docker logs.
          <br />
          Run: <code className="bg-blue-100 px-2 py-1 rounded text-xs font-mono inline-block mt-1">
            docker compose logs manager | grep "ADMIN TOKEN"
          </code>
        </div>
      </div>

      {/* Token input */}
      <div>
        <label className="block text-sm font-semibold text-gray-700 mb-2">
          Paste Your ADMIN_TOKEN
        </label>
        <div className="flex gap-2">
          <input
            type={masked ? "password" : "text"}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="sk-admin-..."
            className="flex-1 px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent font-mono text-sm"
          />
          <button
            onClick={() => setMasked(!masked)}
            className="px-3 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200 transition text-sm font-medium"
          >
            {masked ? "Show" : "Hide"}
          </button>
          <button
            onClick={handleCopy}
            disabled={!token.trim()}
            className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 disabled:cursor-not-allowed transition font-medium flex items-center gap-2"
          >
            <Copy className="w-4 h-4" />
            Copy
          </button>
        </div>
        {copyFeedback && (
          <p className="text-xs mt-2" style={{ color: copyFeedback.includes("✓") ? "#059669" : "#dc2626" }}>
            {copyFeedback}
          </p>
        )}
      </div>

      {/* Security note */}
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-4 flex gap-3 text-sm text-amber-800">
        <Lock className="w-5 h-5 text-amber-600 flex-shrink-0 mt-0.5" />
        <div>
          <strong>Security:</strong> The ADMIN_TOKEN provides full platform access.
          Keep it secure, never share it, and rotate it regularly.
        </div>
      </div>
    </div>
  );
}
