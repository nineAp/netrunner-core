import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Power } from "lucide-react";
import { cn } from "@/lib/utils";
import { useTranslation } from "react-i18next";
import { invoke } from "@tauri-apps/api/core";

export function VpnControl() {
  const [status, setStatus] = useState<"idle" | "connecting" | "connected">(
    "idle",
  );

  const handleToggle = async () => {
    try {
      if (status === "idle") {
        setStatus("connecting");
        await invoke("start_vpn_android", {
          remoteAddress: "62.60.244.156",
        });

        setStatus("connected");
      } else {
        setStatus("idle");
      }
    } catch (error) {
      console.error("Ошибка VPN:", error);
      setStatus("idle");
    }
  };

  const { t } = useTranslation();

  const isActive = status !== "idle";

  const statusMap = {
    idle: t("disconnected"),
    connecting: t("connecting"),
    connected: t("connected"),
  };

  return (
    <div className="flex flex-col items-center justify-center gap-6 p-10">
      {/* Контейнер с эффектом жидкого стекла */}
      <div className="relative flex size-64 items-center justify-center rounded-full bg-background/20 backdrop-blur-xl border border-white/10 shadow-2xl p-4">
        <svg
          className="absolute size-full rotate-90 pointer-events-none"
          viewBox="-20 -20 300 300"
        >
          {/* Фоновая линия */}
          <circle
            cx="130"
            cy="130"
            r="140"
            className="stroke-primary/20 fill-none"
            strokeWidth="4"
          />

          {/* Правая половина (по часовой от 6 к 12) */}
          <motion.circle
            cx="130"
            cy="130"
            r="140"
            className="stroke-primary/80 fill-none drop-shadow-[0_0_3px_var(--color-primary)]"
            strokeWidth="4"
            strokeLinecap="round"
            strokeDasharray="800"
            initial={{ pathLength: 0 }}
            animate={{
              pathLength: isActive ? 0.495 : 0,
              opacity: isActive ? 1 : 0,
            }}
            transition={{ duration: 1.5, ease: "easeInOut" }}
          />

          {/* Левая половина (против часовой от 6 к 12) */}
          <motion.circle
            cx="130"
            cy="130"
            r="140"
            className="stroke-primary/80 fill-none drop-shadow-[0_0_3px_var(--color-primary)]"
            strokeWidth="4"
            strokeLinecap="round"
            strokeDasharray="800"
            // Поворачиваем на 180 градусов относительно центра, чтобы рисовать в другую сторону
            style={{ rotate: 180, originX: "140px", originY: "141px" }}
            initial={{ pathLength: 0 }}
            animate={{
              pathLength: isActive ? 0.495 : 0,
              opacity: isActive ? 1 : 0,
            }}
            transition={{ duration: 1.5, ease: "easeInOut" }}
          />
        </svg>
        <button
          onClick={handleToggle}
          className={cn(
            "relative size-40 rounded-full transition-all duration-700 flex items-center justify-center",
            isActive
              ? "bg-primary/20 shadow-[0_0_40px_var(--color-primary)]"
              : "bg-muted shadow-inner",
          )}
        >
          <Power
            className={cn(
              "size-16 transition-colors duration-500",
              isActive ? "text-primary" : "text-muted-foreground",
            )}
          />
        </button>
      </div>

      {/* Статус */}
      <div className="text-center space-y-1">
        <p className="text-sm uppercase tracking-widest text-muted-foreground font-semibold">
          {t("status_label")}
        </p>
        <AnimatePresence mode="wait">
          <motion.p
            key={status}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -10 }}
            className={cn(
              "text-xl font-bold",
              isActive ? "text-primary" : "text-foreground",
            )}
          >
            {statusMap[status]}
          </motion.p>
        </AnimatePresence>
      </div>
    </div>
  );
}
