import { useState } from "react";
import { useTranslation } from "react-i18next";
import { SettingsToggle } from "@/components/shared/SettingsToggle";
import { ThemeToggle } from "@/features/ThemeToggle";
import { LanguageToggle } from "@/features/ToggleLanguge";
import { useSettings } from "@/hooks/SettingsContext";

export function Settings() {
  const { t } = useTranslation();
  const [killSwitch, setKillSwitch] = useState(false);
  const [stealthMode, setStealthMode] = useState(true);
  const { reduceMotion, setReduceMotion } = useSettings();

  return (
    <div className="w-full max-w-[320px] flex flex-col gap-8 p-6 z-5">
      <h2 className="text-xl font-bold">{t("settings")}</h2>

      {/* Секция: Сеть 
      <div className="space-y-4">
        <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
          {t("section_network")}
        </h3>
        <SettingsToggle
          label={t("kill_switch")}
          description={t("kill_switch_desc")}
          checked={killSwitch}
          onCheckedChange={setKillSwitch}
        />
        <SettingsToggle
          label={t("stealth_mode")}
          description={t("stealth_mode_desc")}
          checked={stealthMode}
          onCheckedChange={setStealthMode}
        />
      </div>
*/}
      {/* Секция: Интерфейс */}
      <div className="space-y-4">
        <h3 className="text-[10px] font-bold text-muted-foreground uppercase tracking-wider">
          {t("section_interface")}
        </h3>

        <SettingsToggle
          label={t("reduce_motion")}
          description={t("reduce_motion_desc")}
          checked={reduceMotion}
          onCheckedChange={setReduceMotion}
        />

        <div className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10">
          <span className="text-sm font-medium">{t("theme_toggle")}</span>
          <ThemeToggle />
        </div>

        <div className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10">
          <span className="text-sm font-medium">{t("language_toggle")}</span>
          <LanguageToggle />
        </div>
      </div>
    </div>
  );
}
