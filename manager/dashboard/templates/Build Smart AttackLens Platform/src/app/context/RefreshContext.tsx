import {
  createContext, useCallback, useContext, useMemo, useReducer, useRef,
  type ReactNode,
} from "react";

export interface RefreshState {
  refreshRevision: number;
  isRefreshing: boolean;
  pendingRequests: number;
  registrationOpen: boolean;
  lastSuccessfulAt: number | null;
  lastError: string | null;
}

type RefreshAction =
  | { type: "trigger" }
  | { type: "request_started"; revision: number }
  | { type: "request_settled"; revision: number; at: number; error?: string }
  | { type: "registration_closed"; revision: number; at: number };

export const initialRefreshState: RefreshState = {
  refreshRevision: 0,
  isRefreshing: false,
  pendingRequests: 0,
  registrationOpen: false,
  lastSuccessfulAt: null,
  lastError: null,
};

export function refreshReducer(state: RefreshState, action: RefreshAction): RefreshState {
  if (action.type === "trigger") {
    return {
      ...state,
      refreshRevision: state.refreshRevision + 1,
      isRefreshing: true,
      pendingRequests: 0,
      registrationOpen: true,
      lastError: null,
    };
  }
  if (action.revision !== state.refreshRevision || !state.isRefreshing) return state;
  if (action.type === "request_started") {
    return { ...state, pendingRequests: state.pendingRequests + 1 };
  }
  if (action.type === "registration_closed") {
    const complete = state.pendingRequests === 0;
    return {
      ...state,
      registrationOpen: false,
      isRefreshing: !complete,
      lastSuccessfulAt: complete && !state.lastError ? action.at : state.lastSuccessfulAt,
    };
  }
  const pendingRequests = Math.max(0, state.pendingRequests - 1);
  const lastError = action.error || state.lastError;
  const complete = !state.registrationOpen && pendingRequests === 0;
  return {
    ...state,
    pendingRequests,
    lastError,
    isRefreshing: !complete,
    lastSuccessfulAt: complete && !lastError ? action.at : state.lastSuccessfulAt,
  };
}

interface RefreshContextValue extends RefreshState {
  /** Backward-compatible alias while callers migrate. */
  refreshNonce: number;
  triggerRefresh: () => void;
  registerRefreshRequest: (revision?: number) => (error?: unknown) => void;
}

const RefreshContext = createContext<RefreshContextValue>({
  ...initialRefreshState,
  refreshNonce: 0,
  triggerRefresh: () => {},
  registerRefreshRequest: () => () => {},
});

export function RefreshProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(refreshReducer, initialRefreshState);
  const stateRef = useRef(state);
  stateRef.current = state;

  const triggerRefresh = useCallback(() => {
    const revision = stateRef.current.refreshRevision + 1;
    dispatch({ type: "trigger" });
    // Give visible consumers one render/effect turn to register. This timer
    // only closes registration; actual requests keep the spinner active.
    window.setTimeout(() => {
      dispatch({ type: "registration_closed", revision, at: Date.now() });
    }, 100);
  }, []);

  const registerRefreshRequest = useCallback((revision?: number) => {
    const current = stateRef.current;
    const target = revision ?? current.refreshRevision;
    if (!current.isRefreshing || target !== current.refreshRevision) return () => {};
    dispatch({ type: "request_started", revision: target });
    let settled = false;
    return (error?: unknown) => {
      if (settled) return;
      settled = true;
      const message = error instanceof Error ? error.message : error ? String(error) : undefined;
      dispatch({ type: "request_settled", revision: target, at: Date.now(), error: message });
    };
  }, []);

  const value = useMemo<RefreshContextValue>(() => ({
    ...state,
    refreshNonce: state.refreshRevision,
    triggerRefresh,
    registerRefreshRequest,
  }), [state, triggerRefresh, registerRefreshRequest]);

  return <RefreshContext.Provider value={value}>{children}</RefreshContext.Provider>;
}

export function useRefresh(): RefreshContextValue {
  return useContext(RefreshContext);
}
