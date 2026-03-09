import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";

interface BurgerMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function BurgerMenu({ isOpen, onClose }: BurgerMenuProps) {
  if (!isOpen) return null;

  return (
    <>
      {/* Затемнение фона при открытом меню */}
      <div
        className="fixed inset-0 z-30 bg-black/20 backdrop-blur-sm"
        onClick={onClose}
      />

      <div className="absolute left-0 top-16 z-40 w-64 h-[calc(100vh-4rem)] bg-card border-r p-6 shadow-xl animate-in slide-in-from-left">
        <nav className="flex flex-col gap-6" onClick={onClose}>
          <Link
            to="/"
            className="text-lg font-medium hover:text-primary transition-colors"
          >
            Подключение
          </Link>
          <Link
            to="/settings"
            className="text-lg font-medium hover:text-primary transition-colors"
          >
            Настройки
          </Link>
          <Link
            to="/about"
            className="text-lg font-medium hover:text-primary transition-colors"
          >
            О программе
          </Link>
        </nav>
      </div>
    </>
  );
}
