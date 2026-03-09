import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "../style.css";
import "./i18n";
import { SettingsProvider } from "./hooks/SettingsContext";

const root = document.getElementById("root");

if (root) {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <SettingsProvider>
      <App />
    </SettingsProvider>,
  );
}
