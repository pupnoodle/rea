import { rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  createIdaTarget,
  RecordingIdaMcp,
} from "../../tests/fixtures/idaMcp.js";
import { idaProtocol, readIdaConfiguration } from "./IdaConfiguration.js";
import type { IdaMcpConnection } from "./IdaMcpConnection.js";
import { IdaSessionClient } from "./IdaSessionClient.js";
import { idaCapabilities } from "./IdaProviderCapabilities.js";

const roots: string[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await rm(root, { recursive: true, force: true });
});

const attachedModernTools = [
  "server_health",
  "list_funcs",
  "lookup_funcs",
  "find_regex",
  "decompile",
  "disasm",
  "callees",
  "xrefs_to",
  "callgraph",
];

describe("attached modern IDA profile", () => {
  it("selects the modern protocol only when a registration asks for it", async () => {
    const { root } = await createIdaTarget();
    roots.push(root);
    const path = join(root, "mcp.json");
    await writeFile(
      path,
      JSON.stringify({ command: "python", args: ["server.py"] }),
    );
    const legacy = readIdaConfiguration(path);
    expect(legacy.ok && idaProtocol(legacy.value)).toBe("legacy");
    await writeFile(
      path,
      JSON.stringify({
        command: "python",
        args: ["server.py"],
        protocol: "modern",
      }),
    );
    const modern = readIdaConfiguration(path);
    expect(modern.ok && idaProtocol(modern.value)).toBe("modern");
  });

  it("identifies the recorded input from the metadata resource without supervisor or legacy calls", async () => {
    const { root, target } = await createIdaTarget();
    roots.push(root);
    const producer = new RecordingIdaMcp(target, "attached");
    const resources: string[] = [];
    const connection: IdaMcpConnection = {
      connect: async () => attachedModernTools,
      call: (name, args) => producer.call(name, args),
      readResource: async (uri) => {
        resources.push(uri);
        return {
          path: target.path,
          module: "target.elf",
          sha256: target.sha256,
          base: "0x1000",
        };
      },
      serverInfo: () => producer.serverInfo(),
      close: () => producer.close(),
    };
    const client = new IdaSessionClient(
      {
        command: "fixture",
        args: [],
        env: {},
        mode: "attached",
        protocol: "modern",
        timeoutMs: 1000,
      },
      target,
      connection,
    );
    expect((await client.execute("health", {})).ok).toBe(true);
    expect((await client.execute("list_procedures", {})).ok).toBe(true);
    expect(resources.length).toBeGreaterThan(0);
    expect(new Set(resources)).toEqual(new Set(["ida://idb/metadata"]));
    const names = producer.calls.map(({ name }) => name);
    expect(names).not.toContain("get_metadata");
    expect(names.some((name) => name.startsWith("idb_"))).toBe(false);
    await client.close();
  });

  it("reports direct callers as unavailable because the modern profile does not prove call edges", () => {
    const callers = idaCapabilities("attached", false, "modern").find(
      ({ operation }) => operation === "procedure_callers",
    );
    expect(callers?.available).toBe(false);
  });
});
