import { cn } from "@/lib/utils";
import { useTranslation } from "react-i18next";

interface VpnStatsProps {
  received: string;
  sent: string;
  className?: string;
}

export function VpnStats({ received, sent, className }: VpnStatsProps) {
  const { t } = useTranslation();
  return (
    <div
      className={cn(
        "w-full max-w-70",
        "relative flex items-center justify-between px-8 py-4 rounded-2xl", // Увеличил отступы внутри
        "bg-background/20 backdrop-blur-md border border-white/10",
        "shadow-[inset_0_1px_1px_rgba(255,255,255,0.4),0_8px_16px_rgba(0,0,0,0.1)]",
        "backdrop-blur-md saturate-150 brightness-110",
        className,
      )}
    >
      {/* Теперь контент внутри растянется равномерно */}
      <div className="flex flex-col items-center flex-1">
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">
          {t("rx")}
        </span>
        <span className="text-sm font-mono text-foreground font-semibold tracking-tight">
          {received}
        </span>
      </div>

      <div className="h-8 w-px bg-border/50 mx-4" />

      <div className="flex flex-col items-center flex-1">
        <span className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">
          {t("tx")}
        </span>
        <span className="text-sm font-mono text-foreground font-semibold tracking-tight">
          {sent}
        </span>
      </div>
    </div>
  );
}
