import { Link } from "react-router-dom";
import { useTranslation } from "react-i18next";
interface BurgerMenuProps {
  isOpen: boolean;
  onClose: () => void;
}

export function BurgerMenu({ isOpen, onClose }: BurgerMenuProps) {
  if (!isOpen) return null;
  const { t } = useTranslation();
  return (
    <>
      {/* затемнение только под хедером */}
      <div
        className="fixed inset-x-0 bottom-0 top-25 z-30 bg-black/20 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* меню */}
      <div className="fixed left-0 top-25 z-60 h-[calc(100vh-4rem)] w-64 bg-card border-r p-6 shadow-xl animate-in slide-in-from-left">
        <nav className="flex flex-col gap-6" onClick={onClose}>
          <Link
            to="/"
            className="text-lg font-medium hover:text-primary transition-colors"
          >
            {t("home_label")}
          </Link>

          <Link
            to="/settings"
            className="text-lg font-medium hover:text-primary transition-colors"
          >
            {t("settings")}
          </Link>

          <Link
            to="/about"
            className="text-lg font-medium hover:text-primary transition-colors"
          >
            {t("about_title")}
          </Link>
        </nav>
      </div>
    </>
  );
}
