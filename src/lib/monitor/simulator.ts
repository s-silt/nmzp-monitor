import { useEffect } from "react";
import { useMonitor } from "./store";

export function useAppChrome() {
  const theme = useMonitor((s) => s.theme);
  const locale = useMonitor((s) => s.locale);
  const hydrate = useMonitor((s) => s.hydrate);
  const syncFromServer = useMonitor((s) => s.syncFromServer);

  useEffect(() => {
    hydrate();
  }, [hydrate]);

  useEffect(() => {
    const t = window.setInterval(() => {
      void syncFromServer();
    }, 5000);
    return () => window.clearInterval(t);
  }, [syncFromServer]);

  useEffect(() => {
    const root = document.documentElement;
    root.dataset.theme = theme;
    root.lang = locale === "zh" ? "zh-CN" : "en";
    root.style.colorScheme = theme;
  }, [theme, locale]);
}
