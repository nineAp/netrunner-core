#!/usr/bin/env node

import { readFileSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { execSync } from "node:child_process";

const SERVER = requireEnv("GITEA_SERVER_URL").replace(/\/$/, "");
const TOKEN = requireEnv("GITEA_TOKEN");
const OWNER = requireEnv("GITEA_OWNER");
const DIST_DIR = process.argv[2] || "dist-openwrt";
const PACKAGE_NAME = "netrunner-client-openwrt";

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`Переменная окружения ${name} обязательна`);
  return value;
}

function url(path) {
  return `${SERVER}/api/packages/${OWNER}${path}`;
}

async function request(path, options = {}) {
  return fetch(url(path), {
    ...options,
    headers: {
      Authorization: `token ${TOKEN}`,
      ...(options.headers || {}),
    },
  });
}

async function deleteVersion(version) {
  const response = await request(`/generic/${PACKAGE_NAME}/${version}`, {
    method: "DELETE",
  });
  if (!response.ok && response.status !== 404) {
    throw new Error(`Не удалось удалить ${version}: HTTP ${response.status}`);
  }
}

async function uploadVersion(version, files) {
  await deleteVersion(version);
  for (const path of files) {
    const fileName = basename(path);
    const response = await request(
      `/generic/${PACKAGE_NAME}/${version}/${encodeURIComponent(fileName)}`,
      {
        method: "PUT",
        headers: { "Content-Type": "application/octet-stream" },
        body: readFileSync(path),
      },
    );
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`Не удалось загрузить ${fileName}@${version}: HTTP ${response.status}: ${body}`);
    }
    console.log(`→ опубликовано: ${PACKAGE_NAME}@${version}/${fileName}`);
  }
}

async function main() {
  const names = readdirSync(DIST_DIR)
    .filter((name) => name.endsWith(".tar.gz") || name === "SHA256SUMS")
    .sort();
  if (names.length < 4) {
    throw new Error(`Ожидались 3 архива и SHA256SUMS в ${DIST_DIR}`);
  }
  const files = names.map((name) => join(DIST_DIR, name));
  const shortSha = execSync("git rev-parse --short HEAD").toString().trim();

  await uploadVersion(shortSha, files);
  await uploadVersion("latest", files);
  console.log(`✅ OpenWrt-клиент опубликован (sha=${shortSha} + latest).`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
