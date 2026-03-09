import { useTranslation } from "react-i18next";

export function About() {
  const { t } = useTranslation();

  return (
    <div className="flex flex-col items-center gap-6 p-6 max-w-[320px] text-center">
      <h2 className="text-2xl font-bold tracking-tight">{t("about_title")}</h2>

      <p className="text-sm text-muted-foreground leading-relaxed">
        {t("about_desc")}
      </p>

      <div className="w-full flex flex-col gap-3">
        <div className="p-4 rounded-xl bg-white/5 border border-white/10 backdrop-blur-sm">
          <h4 className="text-xs font-bold uppercase tracking-widest text-primary mb-1">
            {t("proto_title")}
          </h4>
          <p className="text-[11px] text-muted-foreground">{t("proto_desc")}</p>
        </div>

        <div className="p-4 rounded-xl bg-white/5 border border-white/10 backdrop-blur-sm">
          <h4 className="text-xs font-bold uppercase tracking-widest text-primary mb-1">
            {t("zk_title")}
          </h4>
          <p className="text-[11px] text-muted-foreground">{t("zk_desc")}</p>
        </div>
      </div>

      <div className="text-[10px] text-muted-foreground/60 mt-2">
        {t("version_info")}
        <br />
        {t("footer_text")}
      </div>
    </div>
  );
}
