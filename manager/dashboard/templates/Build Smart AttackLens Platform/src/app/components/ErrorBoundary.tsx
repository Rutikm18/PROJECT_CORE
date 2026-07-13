import { Component, type ReactNode } from "react";
import { AlertTriangle, RefreshCw, Home } from "lucide-react";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  error: Error | null;
  errorInfo: string;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { error: null, errorInfo: "" };
  }

  static getDerivedStateFromError(error: Error): State {
    return { error, errorInfo: error.stack ?? error.message };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error("[ErrorBoundary]", error, info.componentStack);
  }

  reset = () => this.setState({ error: null, errorInfo: "" });

  render() {
    if (this.state.error) {
      if (this.props.fallback) return this.props.fallback;
      return (
        <div className="min-h-[60vh] flex items-center justify-center p-8">
          <div className="max-w-md w-full text-center">
            <div className="w-14 h-14 rounded-2xl bg-red-50 border border-red-100 flex items-center justify-center mx-auto mb-5">
              <AlertTriangle className="w-7 h-7 text-red-400" />
            </div>
            <h2 className="text-base font-semibold text-gray-900 mb-1.5">
              Something went wrong
            </h2>
            <p className="text-[13px] text-gray-500 mb-6 leading-relaxed">
              This page encountered an unexpected error. You can try refreshing
              or return to the dashboard.
            </p>
            <div className="flex gap-2.5 justify-center">
              <button
                onClick={this.reset}
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-[12px] font-medium rounded-lg border border-gray-200 text-gray-700 bg-white hover:bg-gray-50 transition-colors"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                Try again
              </button>
              <a
                href="/dashboard"
                className="inline-flex items-center gap-1.5 px-3.5 py-2 text-[12px] font-medium rounded-lg bg-gray-900 text-white hover:bg-gray-800 transition-colors"
              >
                <Home className="w-3.5 h-3.5" />
                Go to dashboard
              </a>
            </div>
            {import.meta.env.DEV && (
              <details className="mt-6 text-left">
                <summary className="text-[11px] text-gray-400 cursor-pointer hover:text-gray-600">
                  Error details (dev only)
                </summary>
                <pre className="mt-2 text-[10px] text-red-500 bg-red-50 p-3 rounded-lg overflow-auto max-h-40 text-left whitespace-pre-wrap">
                  {this.state.errorInfo}
                </pre>
              </details>
            )}
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
