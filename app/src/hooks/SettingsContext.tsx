import { createContext, useContext, useState, ReactNode } from "react";

const SettingsContext = createContext({
  reduceMotion: false,
  setReduceMotion: (val: boolean) => {},
});

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [reduceMotion, setReduceMotion] = useState(false);
  return (
    <SettingsContext.Provider value={{ reduceMotion, setReduceMotion }}>
      {children}
    </SettingsContext.Provider>
  );
}

export const useSettings = () => useContext(SettingsContext);
