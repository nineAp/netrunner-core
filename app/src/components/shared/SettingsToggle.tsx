import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";

interface SettingsToggleProps {
  label: string;
  description: string;
  checked: boolean;
  onCheckedChange: (checked: boolean) => void;
}

export function SettingsToggle({
  label,
  description,
  checked,
  onCheckedChange,
}: SettingsToggleProps) {
  return (
    <div className="flex items-center justify-between p-4 rounded-xl bg-white/5 border border-white/10 backdrop-blur-sm transition-all hover:bg-white/10">
      <div className="space-y-0.5">
        <Label className="text-sm font-medium text-foreground">{label}</Label>
        <p className="text-[11px] text-muted-foreground">{description}</p>
      </div>
      <Switch
        checked={checked}
        onCheckedChange={onCheckedChange}
        className="data-[state=checked]:bg-primary"
      />
    </div>
  );
}
