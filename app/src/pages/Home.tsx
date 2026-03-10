import { VpnControl } from "../features/VpnControl";
import { VpnStats } from "../features/VpnStats";
import { CountrySelect } from "../features/CountrySelect";

export function Home() {
  return (
    <div className="flex flex-col gap-1.75 items-center">
      <VpnControl />
      <CountrySelect />
      <VpnStats received="0" sent="0" />
    </div>
  );
}
