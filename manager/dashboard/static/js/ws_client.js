/** ws_client.js — WebSocket with reconnect + heartbeat */

export class WsClient {
  constructor(url, onMessage) {
    this.url       = url;
    this.onMessage = onMessage;
    this._ws       = null;
    this._delay    = 1000;
    this._stopped  = false;
    this._ping     = null;
  }

  connect() {
    this._stopped = false;
    this._open();
  }

  disconnect() {
    this._stopped = true;
    clearInterval(this._ping);
    if (this._ws) this._ws.close();
  }

  _open() {
    if (this._stopped) return;
    this._ws = new WebSocket(this.url);

    this._ws.onopen = () => {
      console.log("[ws] connected");
      this._delay = 1000;
      this._ping  = setInterval(() => {
        if (this._ws?.readyState === WebSocket.OPEN)
          this._ws.send("ping");
      }, 25_000);
    };

    this._ws.onmessage = (ev) => {
      try { this.onMessage(JSON.parse(ev.data)); }
      catch { /* ignore parse errors */ }
    };

    this._ws.onclose = () => {
      clearInterval(this._ping);
      if (!this._stopped) {
        const d = this._delay;
        this._delay = Math.min(this._delay * 2, 30_000);
        console.log(`[ws] reconnecting in ${d}ms`);
        setTimeout(() => this._open(), d);
      }
    };

    this._ws.onerror = (e) => console.warn("[ws] error", e);
  }
}
