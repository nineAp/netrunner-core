import { useSettings } from "@/hooks/SettingsContext";
import { motion } from "framer-motion";

export function AnimatedBackground() {
  const { reduceMotion } = useSettings();
  if (reduceMotion) {
    return <div className="fixed inset-0 w-full h-full bg-background -z-10" />;
  }

  return (
    <div className="fixed w-full h-full">
      {/* Каустические пятна (используем контрастные Tailwind цвета) */}

      <svg className="absolute w-0 h-0">
        <defs>
          <filter id="blob-filter">
            <feGaussianBlur in="SourceGraphic" stdDeviation="40" />
          </filter>
        </defs>
      </svg>

      <div
        className="absolute inset-0"
        style={{ filter: "url(#blob-filter)", isolation: "isolate" }}
      >
        <motion.div
          className="absolute top-[-10%] left-[-10%] w-[60%] h-[60%] rounded-full bg-chart-1/20"
          animate={{
            x: [0, 100, 0],
            y: [0, 50, 0],
            rotate: [0, 90, 0],
          }}
          style={{ willChange: "transform" }}
          transition={{ duration: 20, repeat: Infinity, ease: "easeInOut" }}
        />

        <motion.div
          className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] rounded-full bg-chart-2/20"
          animate={{
            x: [0, -50, 0],
            y: [0, 100, 0],
            rotate: [0, -45, 0],
          }}
          style={{ willChange: "transform" }}
          transition={{ duration: 15, repeat: Infinity, ease: "easeInOut" }}
        />

        <motion.div
          className="absolute top-[20%] right-[10%] w-[40%] h-[40%] rounded-full bg-chart-3/20"
          animate={{
            scale: [1, 1.2, 1],
            opacity: [0.3, 0.6, 0.3],
          }}
          style={{ willChange: "transform" }}
          transition={{ duration: 10, repeat: Infinity, ease: "easeInOut" }}
        />

        <motion.div
          className="absolute bottom-[20%] left-[20%] w-[30%] h-[30%] rounded-full bg-chart-3/20 "
          animate={{
            x: [0, 30, 0],
            y: [0, -30, 0],
          }}
          style={{ willChange: "transform" }}
          transition={{ duration: 8, repeat: Infinity, ease: "easeInOut" }}
        />
      </div>
    </div>
  );
}
