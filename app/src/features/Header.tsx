import { Menu } from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "./ThemeToggle";

export function Header({ onMenuClick }: { onMenuClick: () => void }) {
  return (
    <header className="sticky top-0 z-50 w-full border-b border-border/40 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 shadow-sm pt-[env(safe-area-inset-top)]">
      {/* Используем grid для идеальной центровки */}
      <div className="grid h-16 w-full grid-cols-[auto_1fr_auto] items-center px-4">
        {/* Слева: Бургер (занимает место по контенту) */}
        <div className="flex justify-start">
          <Button variant="ghost" size="icon" onClick={onMenuClick}>
            <Menu className="size-6" />
          </Button>
        </div>

        {/* По центру: Лого (занимает всё свободное пространство и центрирует контент) */}
        <div className="flex justify-center">
          <h1 className="text-xl font-bold tracking-tighter">
            Netrunner <span className="text-primary italic">VPN</span>
          </h1>
        </div>

        {/* Справа: Тема (занимает место по контенту) */}
        <div className="flex justify-end">
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}
