import { describe, expect, test } from "bun:test";
import {
  checkKeyTransparencyProviderConformance,
  createKeyTransparencyClient,
  createMemoryKeyTransparencyViewStore,
  keyTransparencyValueDigest,
} from "@absolutejs/key-transparency";
import {
  MEMORY_KEY_TRANSPARENCY_PROTOCOL,
  createMemoryKeyTransparencyProvider,
} from "../src";

const now = 1_800_000_000_000;
const label = { bytes: new TextEncoder().encode("opaque-user-label") };

const setup = async () => {
  let authorizationChecks = 0;
  const provider = await createMemoryKeyTransparencyProvider({
    logId: "memory-test-log",
    now: () => now,
    verifyUpdateAuthorization: ({ authorization }) => {
      authorizationChecks += 1;
      return authorization[0] === 42;
    },
  });
  const client = createKeyTransparencyClient({
    now: () => now,
    provider,
    store: createMemoryKeyTransparencyViewStore(),
  });
  return { authorizationChecks: () => authorizationChecks, client, provider };
};

describe("memory key-transparency provider", () => {
  test("uses a distinct non-IETF development protocol", async () => {
    const { provider } = await setup();
    expect(provider.manifest.protocolRevision).toBe(
      MEMORY_KEY_TRANSPARENCY_PROTOCOL,
    );
    expect(provider.manifest.security.assurance).toBe("experimental");
    expect(provider.manifest.security.splitViewDetection).toBe(false);
  });

  test("authorizes, records, searches, and monitors an update", async () => {
    const { authorizationChecks, client } = await setup();
    const value = new Uint8Array([7, 8, 9]);
    const updated = await client.update({
      authorization: new Uint8Array([42]),
      label,
      value,
    });
    value.fill(0);
    expect(updated.version).toBe(0);
    expect(updated.valueDigest).toBe(
      await keyTransparencyValueDigest(new Uint8Array([7, 8, 9])),
    );
    expect(authorizationChecks()).toBe(1);

    const found = await client.search({ label });
    expect(found.value).toEqual(new Uint8Array([7, 8, 9]));
    found.value?.fill(0);
    expect((await client.search({ label })).value).toEqual(
      new Uint8Array([7, 8, 9]),
    );

    const monitored = await client.monitorOwner({ labels: [label] });
    expect(monitored.status).toBe("consistent");
  });

  test("rejects an unauthorized update without changing the log", async () => {
    const { client } = await setup();
    await expect(
      client.update({
        authorization: new Uint8Array([0]),
        label,
        value: new Uint8Array([1]),
      }),
    ).rejects.toThrow("was not authorized");
    const result = await client.search({ label });
    expect(result.value).toBeUndefined();
    expect(result.version).toBeUndefined();
  });

  test("rejects altered prior views", async () => {
    const { provider } = await setup();
    const first = await provider.search({ label });
    await expect(
      provider.search({
        label,
        priorView: {
          ...first.view,
          head: {
            ...first.view.head,
            rootHash: new Uint8Array([99]),
          },
        },
      }),
    ).rejects.toThrow("was not issued by this log");
  });

  test("passes provider-neutral conformance", async () => {
    const result = await checkKeyTransparencyProviderConformance({
      createProvider: async () => (await setup()).provider,
      fixtureLabel: new Uint8Array([1, 2, 3]),
      now: () => now,
    });
    expect(result).toEqual({ issues: [], passed: true });
  });
});
