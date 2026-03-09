import { useState } from "react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Globe } from "lucide-react";
import { useTranslation } from "react-i18next";
import ReactCountryFlag from "react-country-flag";
import { cn } from "@/lib/utils";

const countries = [
  { code: "us", name: "United States" },
  { code: "de", name: "Germany" },
  { code: "jp", name: "Japan" },
];

export function CountrySelect() {
  const { t } = useTranslation();
  const [selectedCode, setSelectedCode] = useState<string>("");

  const selectedCountry = countries.find((c) => c.code === selectedCode);

  return (
    <Select onValueChange={setSelectedCode} value={selectedCode}>
      <SelectTrigger className="w-[280px] h-12 bg-white/5 backdrop-blur-lg border-white/10 hover:bg-white/10 transition-all rounded-xl shadow-lg ring-offset-0 focus:ring-0">
        <div
          className={cn(
            "flex items-center gap-2 w-full px-3",
            selectedCountry ? "justify-start" : "justify-center",
          )}
        >
          <span className="truncate flex-1 text-left">
            <SelectValue placeholder={t("select_location_placeholder")} />
          </span>
        </div>
      </SelectTrigger>

      <SelectContent
        className="bg-white/10 backdrop-blur-2xl border-white/10 rounded-xl overflow-hidden"
        style={{ width: "var(--radix-select-trigger-width)" }}
      >
        {countries.map((country) => (
          <SelectItem
            key={country.code}
            value={country.code}
            className="cursor-pointer hover:bg-white/10 focus:bg-white/20 transition-colors"
          >
            <div className="flex items-center gap-3">
              <ReactCountryFlag
                countryCode={country.code.toUpperCase()}
                svg
                className="size-5 rounded-sm"
              />
              <span className="font-medium text-foreground">
                {country.name}
              </span>
            </div>
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
