import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useDarkMode } from "@/hooks/useDarkMode";

export function ThemeToggle() {
  const { isDark, toggleDark } = useDarkMode();

  return (
    <Button
      variant="outline"
      size="icon"
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        toggleDark();
      }}
      className="rounded-full transition-all duration-300 hover:scale-105"
    >
      {isDark ? (
        <Sun className="h-[1.2rem] w-[1.2rem]" />
      ) : (
        <Moon className="h-[1.2rem] w-[1.2rem]" />
      )}
      <span className="sr-only">Переключить тему</span>
    </Button>
  );
}
