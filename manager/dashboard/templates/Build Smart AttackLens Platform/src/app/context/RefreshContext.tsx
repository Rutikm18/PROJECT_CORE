import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

interface RefreshContextValue {
  refreshNonce: number;
  triggerRefresh: () => void;
  isRefreshing: boolean;
}

const RefreshContext = createContext<RefreshContextValue>({
  refreshNonce: 0,
  triggerRefresh: () => {},
  isRefreshing: false,
});

export function RefreshProvider({ children }: { children: ReactNode }) {
  const [refreshNonce, setRefreshNonce] = useState(0);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const triggerRefresh = useCallback(() => {
    setRefreshNonce(n => n + 1);
    setIsRefreshing(true);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setIsRefreshing(false), 2000);
  }, []);

  return (
    <RefreshContext.Provider value={{ refreshNonce, triggerRefresh, isRefreshing }}>
      {children}
    </RefreshContext.Provider>
  );
}

export function useRefresh(): RefreshContextValue {
  return useContext(RefreshContext);
}
