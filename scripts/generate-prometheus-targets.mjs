#!/usr/bin/env node
// Генерит targets-файл для Prometheus file_sd_configs (см.
// netrunner-data/observability/prometheus.yml, job "netrunner-proxy-nodes")
// из nodes.json этого репозитория — список нод меняется независимо от
// прод-конфига Prometheus, руками синхронизировать его на каждый деплой
// ноды неудобно и хрупко.
//
// Порт метрик у всех нод одинаковый (9093 — см. server/netrunner-server.service,
// templates/init_node.sh в netrunner-backend, .gitea/workflows/deploy.yml
// здесь же), меняется только host — поэтому в самом nodes.json отдельного
// поля под него нет.
//
// Использование: node scripts/generate-prometheus-targets.mjs nodes.json > targets.json
import { readFileSync } from "node:fs";

const METRICS_PORT = 9093;

const [, , nodesPath] = process.argv;
if (!nodesPath) {
  console.error("Использование: generate-prometheus-targets.mjs <nodes.json>");
  process.exit(1);
}

const nodes = JSON.parse(readFileSync(nodesPath, "utf-8"));

const targets = nodes
  .filter((n) => !n.host?.startsWith("CHANGE_ME"))
  .map((n) => ({
    targets: [`${n.host}:${METRICS_PORT}`],
    labels: { node: n.name },
  }));

process.stdout.write(JSON.stringify(targets, null, 2) + "\n");
