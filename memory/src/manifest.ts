import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["app-developers", "test-engineers", "security-teams"],
    intents: [
      "test key transparency integrations",
      "run key transparency conformance locally",
    ],
    keywords: ["key transparency", "memory", "testing", "development"],
    protocols: ["Absolute memory key transparency v1"],
  },
  identity: {
    accent: "#8b5cf6",
    category: "security",
    description:
      "Development-only process-local signed append-only key directory for AbsoluteJS key-transparency tests and examples.",
    docsUrl:
      "https://github.com/absolutejs/key-transparency-providers/tree/main/memory",
    name: "@absolutejs/key-transparency-memory",
    tagline:
      "Exercise key-transparency integrations without a production claim.",
  },
  settings: Type.Object({}, { additionalProperties: false }),
  wiring: [],
});
