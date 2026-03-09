import { VpnControl } from "../features/VpnControl";
import { VpnStats } from "../features/VpnStats";
import { CountrySelect } from "../features/CountrySelect";

export function Home() {
  return (
    <>
      <VpnControl />
      <CountrySelect />
      <VpnStats received="0" sent="0" />
    </>
  );
}
