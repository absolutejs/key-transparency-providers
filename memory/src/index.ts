import {
  keyTransparencyLabelDigest,
  keyTransparencyValueDigest,
  type KeyTransparencyEvidence,
  type KeyTransparencyEvidenceOperation,
  type KeyTransparencyLabel,
  type KeyTransparencyMonitoredChange,
  type KeyTransparencyProvider,
  type KeyTransparencyVerifiedView,
} from "@absolutejs/key-transparency";

export const MEMORY_KEY_TRANSPARENCY_PROTOCOL =
  "absolute-memory-key-transparency-v1" as const;

const MAX_AUTHORIZATION_BYTES = 8_192;
const MAX_LABEL_BYTES = 1_024;
const MAX_MONITORED_LABELS = 100;
const MAX_VALUE_BYTES = 65_536;

type MemoryEntry = {
  readonly labelDigest: string;
  readonly previousValueDigest?: string;
  readonly timestamp: number;
  readonly value: Uint8Array;
  readonly valueDigest: string;
  readonly version: number;
};

type MemoryValue = {
  readonly value: Uint8Array;
  readonly valueDigest: string;
  readonly version: number;
};

export type MemoryKeyTransparencyProviderOptions = {
  readonly logId: string;
  readonly now?: () => number;
  readonly verifyUpdateAuthorization: (input: {
    readonly authorization: Uint8Array;
    readonly label: KeyTransparencyLabel;
    readonly value: Uint8Array;
  }) => boolean | Promise<boolean>;
};

const encodeBase64Url = (value: Uint8Array): string =>
  globalThis
    .btoa(Array.from(value, (byte) => String.fromCharCode(byte)).join(""))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");

const encode = (value: unknown): Uint8Array =>
  new TextEncoder().encode(JSON.stringify(value));

const hash = async (value: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(
    await crypto.subtle.digest("SHA-256", new Uint8Array([...value])),
  );

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length &&
  left.every((byte, index) => byte === right[index]);

const cloneView = (
  view: KeyTransparencyVerifiedView,
): KeyTransparencyVerifiedView => ({
  fullTreeHead: view.fullTreeHead.slice(),
  head: {
    ...view.head,
    rootHash: view.head.rootHash.slice(),
    signedTreeHead: view.head.signedTreeHead.slice(),
  },
});

const assertLabel = (label: KeyTransparencyLabel): void => {
  if (label.bytes.length === 0 || label.bytes.length > MAX_LABEL_BYTES) {
    throw new Error("Opaque key-transparency label has an invalid size.");
  }
};

export const createMemoryKeyTransparencyProvider = async (
  options: MemoryKeyTransparencyProviderOptions,
): Promise<KeyTransparencyProvider> => {
  if (options.logId.trim() === "") throw new Error("logId must not be empty.");
  const now = options.now ?? Date.now;
  const signingKeys = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    false,
    ["sign", "verify"],
  );
  const genesis = encode({
    domain: MEMORY_KEY_TRANSPARENCY_PROTOCOL,
    logId: options.logId,
  });
  const entries: MemoryEntry[] = [];
  const values = new Map<string, MemoryValue>();
  const views = new Map<number, KeyTransparencyVerifiedView>();
  let mutation = Promise.resolve();

  const createView = async (): Promise<KeyTransparencyVerifiedView> => {
    const treeSize = entries.length + 1;
    const rootHash = await hash(
      encode({
        entries: [
          encodeBase64Url(genesis),
          ...entries.map((entry) => ({
            labelDigest: entry.labelDigest,
            previousValueDigest: entry.previousValueDigest ?? null,
            timestamp: entry.timestamp,
            valueDigest: entry.valueDigest,
            version: entry.version,
          })),
        ],
        logId: options.logId,
        protocol: MEMORY_KEY_TRANSPARENCY_PROTOCOL,
      }),
    );
    const timestamp = entries.at(-1)?.timestamp ?? now();
    const fullTreeHead = encode({
      logId: options.logId,
      rootHash: encodeBase64Url(rootHash),
      timestamp,
      treeSize,
    });
    const signature = new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        signingKeys.privateKey,
        new Uint8Array([...fullTreeHead]),
      ),
    );
    const view = {
      fullTreeHead,
      head: {
        logId: options.logId,
        rootHash,
        signedTreeHead: signature,
        timestamp,
        treeSize,
      },
    } satisfies KeyTransparencyVerifiedView;
    views.set(treeSize, cloneView(view));
    return view;
  };

  await createView();

  const currentView = async () =>
    cloneView(views.get(entries.length + 1) ?? (await createView()));

  const assertPrior = (
    prior: KeyTransparencyVerifiedView | undefined,
  ): void => {
    if (prior === undefined) return;
    const known = views.get(prior.head.treeSize);
    if (
      known === undefined ||
      prior.head.logId !== options.logId ||
      !equalBytes(prior.head.rootHash, known.head.rootHash) ||
      !equalBytes(prior.head.signedTreeHead, known.head.signedTreeHead) ||
      !equalBytes(prior.fullTreeHead, known.fullTreeHead)
    ) {
      throw new Error("Prior transparency view was not issued by this log.");
    }
  };

  const evidence = async (
    operation: KeyTransparencyEvidenceOperation,
    subjectDigests: readonly string[],
    view: KeyTransparencyVerifiedView,
  ): Promise<KeyTransparencyEvidence> => ({
    auditorReceipts: [],
    operation,
    protocolRevision: MEMORY_KEY_TRANSPARENCY_PROTOCOL,
    providerId: "memory",
    subjectDigests,
    treeHeadHash: encodeBase64Url(view.head.rootHash),
    verifiedAt: now(),
  });

  return {
    manifest: {
      contract: 1,
      costModel: "free",
      description:
        "Development-only process-local signed append-only key directory.",
      id: "memory",
      logId: options.logId,
      packageName: "@absolutejs/key-transparency-memory",
      protocolRevision: MEMORY_KEY_TRANSPARENCY_PROTOCOL,
      roles: ["client", "log", "monitor"],
      runtimes: ["browser", "bun", "node"],
      security: {
        assurance: "experimental",
        contactMonitoring: true,
        independentlyOperatedAuditor: false,
        ownerMonitoring: true,
        privateLookups: true,
        splitViewDetection: false,
        thirdPartyAuditing: false,
      },
      version: "0.2.0",
    },
    monitor: async ({ labels, mode, priorView }) => {
      if (labels.length === 0 || labels.length > MAX_MONITORED_LABELS) {
        throw new Error("Monitoring label count is invalid.");
      }
      labels.forEach(assertLabel);
      assertPrior(priorView);
      const labelDigests = await Promise.all(
        labels.map(keyTransparencyLabelDigest),
      );
      const allowed = new Set(labelDigests);
      const startingEntry = Math.max(0, (priorView?.head.treeSize ?? 1) - 1);
      const changes: KeyTransparencyMonitoredChange[] = entries
        .slice(startingEntry)
        .filter((entry) => allowed.has(entry.labelDigest))
        .map((entry) => ({
          currentValueDigest: entry.valueDigest,
          labelDigest: entry.labelDigest,
          previousValueDigest: entry.previousValueDigest,
          version: entry.version,
        }));
      const view = await currentView();
      return {
        changes,
        evidence: await evidence(
          mode === "contact" ? "contact-monitor" : "owner-monitor",
          labelDigests,
          view,
        ),
        status: "consistent",
        view,
      };
    },
    search: async ({ label, priorView }) => {
      assertLabel(label);
      assertPrior(priorView);
      const labelDigest = await keyTransparencyLabelDigest(label);
      const found = values.get(labelDigest);
      const view = await currentView();
      return {
        evidence: await evidence("search", [labelDigest], view),
        ...(found === undefined
          ? {}
          : { value: found.value.slice(), version: found.version }),
        view,
      };
    },
    update: async ({ authorization, label, priorView, value }) => {
      assertLabel(label);
      assertPrior(priorView);
      if (
        authorization.length === 0 ||
        authorization.length > MAX_AUTHORIZATION_BYTES ||
        value.length === 0 ||
        value.length > MAX_VALUE_BYTES
      ) {
        throw new Error("Update authorization or value has an invalid size.");
      }
      if (
        !(await options.verifyUpdateAuthorization({
          authorization: authorization.slice(),
          label: { bytes: label.bytes.slice() },
          value: value.slice(),
        }))
      ) {
        throw new Error("Key-transparency update was not authorized.");
      }

      let resolveMutation: (() => void) | undefined;
      const previousMutation = mutation;
      mutation = new Promise<void>((resolve) => {
        resolveMutation = resolve;
      });
      await previousMutation;
      try {
        const labelDigest = await keyTransparencyLabelDigest(label);
        const valueDigest = await keyTransparencyValueDigest(value);
        const previous = values.get(labelDigest);
        const version = (previous?.version ?? -1) + 1;
        const timestamp = now();
        entries.push({
          labelDigest,
          previousValueDigest: previous?.valueDigest,
          timestamp,
          value: value.slice(),
          valueDigest,
          version,
        });
        values.set(labelDigest, {
          value: value.slice(),
          valueDigest,
          version,
        });
        const view = await createView();
        return {
          evidence: await evidence("update", [labelDigest], view),
          valueDigest,
          version,
          view,
        };
      } finally {
        resolveMutation?.();
      }
    },
  };
};
