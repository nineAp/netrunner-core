import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";

export function LanguageToggle() {
  const { i18n } = useTranslation();

  const toggleLanguage = () => {
    const newLang = i18n.language === "en" ? "ru" : "en";
    i18n.changeLanguage(newLang);
    localStorage.setItem("lang", newLang); // Сохраняем выбор
  };

  return (
    <Button variant="ghost" onClick={toggleLanguage}>
      {i18n.language.toUpperCase()}
    </Button>
  );
}
