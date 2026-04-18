/**
 * useKeybindings — React context + hook that lets interactive components
 * register their active keybindings so the shared `KeybindFooter` can render
 * an accurate hint row without every component hard-coding its own footer.
 *
 * Registrations are stacked LIFO — the most recently-mounted set wins, so
 * focus/mode switches swap the visible hints automatically.
 */
import {
  createContext,
  createElement,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

export interface Keybinding {
  keys: string;
  label: string;
  secondary?: boolean;
}

export interface KeybindingsContextValue {
  bindings: ReadonlyArray<Keybinding>;
  register: (bindings: ReadonlyArray<Keybinding>) => () => void;
}

const EMPTY_CTX: KeybindingsContextValue = {
  bindings: [],
  register: () => () => {
    /* noop when no provider */
  },
};

const Ctx = createContext<KeybindingsContextValue | null>(null);

export function useKeybindings(): KeybindingsContextValue {
  const value = useContext(Ctx);
  return value ?? EMPTY_CTX;
}

export function KeybindingsProvider(props: { children: ReactNode }): JSX.Element {
  const mapRef = useRef<Map<symbol, ReadonlyArray<Keybinding>>>(new Map());
  const orderRef = useRef<symbol[]>([]);
  const [version, setVersion] = useState(0);

  const register = useCallback((bindings: ReadonlyArray<Keybinding>) => {
    const id = Symbol("keybindings");
    mapRef.current.set(id, bindings);
    orderRef.current.push(id);
    setVersion((v) => v + 1);
    return () => {
      mapRef.current.delete(id);
      const idx = orderRef.current.indexOf(id);
      if (idx >= 0) orderRef.current.splice(idx, 1);
      setVersion((v) => v + 1);
    };
  }, []);

  // biome-ignore lint/correctness/useExhaustiveDependencies: `version` is the intentional re-render trigger for ref-backed state
  const value = useMemo<KeybindingsContextValue>(() => {
    const last = orderRef.current[orderRef.current.length - 1];
    const current = last ? (mapRef.current.get(last) ?? []) : [];
    return { bindings: current, register };
  }, [register, version]);

  return createElement(Ctx.Provider, { value }, props.children);
}

function cacheKey(bindings: ReadonlyArray<Keybinding>): string {
  return bindings
    .map((b) => `${b.keys}\u241F${b.label}\u241F${b.secondary ? 1 : 0}`)
    .join("\u241E");
}

/**
 * Register keybindings for the lifetime of the calling component. Safe to
 * call without a provider (becomes a no-op).
 */
export function useRegisterKeybindings(bindings: ReadonlyArray<Keybinding>): void {
  const ctx = useContext(Ctx);
  const register = ctx?.register;
  const key = cacheKey(bindings);
  const bindingsRef = useRef(bindings);
  bindingsRef.current = bindings;
  // biome-ignore lint/correctness/useExhaustiveDependencies: re-register only when logical binding set changes (via cache key), not when the array identity does
  useEffect(() => {
    if (!register) return;
    return register(bindingsRef.current);
  }, [register, key]);
}
