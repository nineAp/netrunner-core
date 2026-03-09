import { useEffect, useState } from "react";

export const useDarkMode = () => {
  const [isDark, setIsDark] = useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem("theme") === "dark";
  });

  useEffect(() => {
    // Слушатель для изменений в localStorage из других компонентов/окон
    const handleStorageChange = () => {
      const isDarkMode = localStorage.getItem("theme") === "dark";
      setIsDark(isDarkMode);
      document.documentElement.classList.toggle("dark", isDarkMode);
    };

    window.addEventListener("storage", handleStorageChange);
    return () => window.removeEventListener("storage", handleStorageChange);
  }, []);

  const toggleDark = () => {
    const nextDark = !isDark;
    setIsDark(nextDark);
    document.documentElement.classList.toggle("dark", nextDark);
    localStorage.setItem("theme", nextDark ? "dark" : "light");

    // ВАЖНО: вручную вызываем событие, чтобы другие компоненты в том же окне узнали об изменении
    window.dispatchEvent(new Event("storage"));
  };

  return { isDark, toggleDark };
};
