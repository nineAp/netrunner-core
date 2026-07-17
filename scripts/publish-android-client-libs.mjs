#!/usr/bin/env node
// Публикует собранные Android-библиотеки клиента (netrunner-client +
// netrunner-logger, по 4 ABI, плюс сгенерённые uniffi Kotlin-биндинги) как
// generic-пакет в Package Registry САМОЙ Gitea — единый источник правды,
// откуда их забирает netrunner-app в CI (см. fetch-client-libs.mjs там же).
//
// Раньше эти файлы существовали только на диске у одного разработчика:
// `make build-android` в этом репозитории rsync'ил gen/ в СОСЕДНИЙ checkout
// netrunner-app по машинно-специфичным путям из .env (ANDROID_BUILD_SRC/
// ANDROID_PROJECT_LIBS) — работало только на этой одной машине и никогда не
// попадало в git (jniLibs/uniffi у vpn-plugin в .gitignore, и правильно —
// это сборочные артефакты). Из-за этого свежий чекаут (в т.ч. любой CI)
// никогда не мог собрать Android: `VpnPlugin.kt` не находил
// `uniffi.netrunner_client.Session/SessionManager`.
//
// Ожидает уже собранный `gen/` (см. Makefile::build-android или
// .gitea/workflows/build.yml::build-android-libs — тот же bindgen-tool +
// cargo-ndk шаг) — сам этот скрипт только переупаковывает и заливает.
//
// Пакеты Gitea принадлежат АККАУНТУ, не репозиторию (см. комментарий в
// build.yml) — нужен только GITEA_OWNER, не полный "owner/repo".
//
// Публикует ДВЕ версии одного и того же архива:
//   - <короткий sha> — неизменяемая, для точной трассировки/отката;
//   - "latest"        — подвижная (удаляем старую версию перед заливкой,
//     Gitea не даёт перезаписать файл в уже существующей версии пакета) —
//     её и тянет netrunner-app по умолчанию, не привязываясь к конкретному
//     коммиту прокси.
//
// Секреты/переменные (Gitea repo Settings):
//   GITEA_TOKEN        — токен с правом write:package
//   GITEA_SERVER_URL   — https://gitea.netrunner-vpn.com
//   GITEA_OWNER        — nineap

import { readFileSync, readdirSync, mkdirSync, cpSync, existsSync } from "node:fs";
import { join } from "node:path";
import { execSync } from "node:child_process";

const GITEA_SERVER_URL = requireEnv("GITEA_SERVER_URL").replace(/\/$/, "");
const GITEA_TOKEN = requireEnv("GITEA_TOKEN");
const GITEA_OWNER = requireEnv("GITEA_OWNER");
const GEN_DIR = process.argv[2] || "gen";

const PACKAGE_NAME = "netrunner-client-android";
const ABIS = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];
const LIBS = ["libnetrunner_client.so", "libnetrunner_logger.so"];

function requireEnv(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Переменная окружения ${name} обязательна`);
  return v;
}

function packageApiUrl(path) {
  return `${GITEA_SERVER_URL}/api/packages/${GITEA_OWNER}${path}`;
}

async function giteaFetch(path, options = {}) {
  const res = await fetch(packageApiUrl(path), {
    ...options,
    headers: {
      Authorization: `token ${GITEA_TOKEN}`,
      ...(options.headers || {}),
    },
  });
  return res;
}

/** Складывает jniLibs/<abi>/*.so + java/uniffi/... в верном для Android-проекта
 * виде (см. tauri-plugin-vpn/android/src/main/{jniLibs,java}) и архивирует. */
function buildArchive(stagingDir) {
  for (const abi of ABIS) {
    const abiDir = join(GEN_DIR, abi);
    if (!existsSync(abiDir)) {
      throw new Error(`Не найден ${abiDir} — build-android для этого ABI не отработал?`);
    }
    const destDir = join(stagingDir, "jniLibs", abi);
    mkdirSync(destDir, { recursive: true });
    for (const lib of LIBS) {
      const src = join(abiDir, lib);
      if (!existsSync(src)) {
        throw new Error(`Не найден ${src} — ожидались обе cdylib (client + logger)`);
      }
      cpSync(src, join(destDir, lib));
    }
  }

  const kotlinSrc = join(GEN_DIR, "uniffi", "netrunner_client", "netrunner_client.kt");
  if (!existsSync(kotlinSrc)) {
    throw new Error(`Не найден ${kotlinSrc} — bindgen-tool не отработал?`);
  }
  const kotlinDestDir = join(stagingDir, "java", "uniffi", "netrunner_client");
  mkdirSync(kotlinDestDir, { recursive: true });
  cpSync(kotlinSrc, join(kotlinDestDir, "netrunner_client.kt"));

  const archivePath = `${stagingDir}.tar.gz`;
  // Архивируем СОДЕРЖИМОЕ stagingDir (jniLibs/, java/ как корень архива), не
  // саму папку staging — иначе на приёмной стороне пришлось бы знать её имя.
  execSync(`tar -czf "${archivePath}" -C "${stagingDir}" jniLibs java`);
  return archivePath;
}

/** Удаляет версию пакета, если она уже существует (нужно для "latest" —
 * Gitea не разрешает залить файл поверх уже существующей версии). */
async function deleteVersionIfExists(version) {
  const res = await giteaFetch(
    `/generic/${PACKAGE_NAME}/${version}`,
    { method: "DELETE" },
  );
  if (!res.ok && res.status !== 404) {
    const text = await res.text().catch(() => "");
    throw new Error(`Не удалось удалить версию ${version}: HTTP ${res.status}: ${text}`);
  }
}

async function uploadVersion(version, archivePath, fileName) {
  await deleteVersionIfExists(version);
  const data = readFileSync(archivePath);
  const res = await giteaFetch(`/generic/${PACKAGE_NAME}/${version}/${fileName}`, {
    method: "PUT",
    headers: { "Content-Type": "application/octet-stream" },
    body: data,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Не удалось загрузить ${fileName}@${version}: HTTP ${res.status}: ${text}`);
  }
  console.log(`→ опубликовано: ${PACKAGE_NAME}@${version}/${fileName}`);
}

async function main() {
  const shortSha = execSync("git rev-parse --short HEAD").toString().trim();
  const stagingDir = "gen-package-staging";
  const archivePath = buildArchive(stagingDir);
  const fileName = "netrunner-client-android.tar.gz";

  await uploadVersion(shortSha, archivePath, fileName);
  await uploadVersion("latest", archivePath, fileName);

  console.log(`✅ Android-либы клиента опубликованы (sha=${shortSha} + latest).`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
