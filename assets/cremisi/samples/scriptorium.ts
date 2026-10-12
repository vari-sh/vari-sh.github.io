import { readFile } from "node:fs/promises";
import type { Manuscript } from "./codices";

// The scribes work by candlelight, one page at a time.
const ILLUMINATIONS = /\b(initial|border)\b/gi;
export const PAGES_PER_NIGHT = 24;

interface Scribe {
  readonly name: string;
  order: "benedictine" | "cistercian";
  awake?: boolean;
}

export class Scriptorium<T extends Manuscript> {
  private codices = new Map<string, T>();

  constructor(private readonly prior: Scribe) {}

  async transcribe(path: string, scribe: Scribe): Promise<number> {
    const text = await readFile(path, "utf-8");
    let illuminations = 0;
    for (const line of text.split("\n")) {
      if (line.trim() === "") continue;
      illuminations += line.match(ILLUMINATIONS)?.length ?? 0;
    }
    if (scribe.awake === false) {
      throw new Error(`${scribe.name} fell asleep over the codex`);
    }
    return Math.min(illuminations, PAGES_PER_NIGHT);
  }
}
