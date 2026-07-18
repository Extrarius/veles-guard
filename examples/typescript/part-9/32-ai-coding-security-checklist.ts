// Illustrative examples for notes/part-9-ai-coding-security/32-ai-coding-security-checklist.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Severity {
  Critical = "Critical",
  High = "High",
  Medium = "Medium",
  Low = "Low",
}

enum Status {
  Yes = "Yes",
  Partial = "Partial",
  No = "No",
  NA = "N/A",
}

interface Item {
  id: string;
  title: string;
  severity: Severity;
  status: Status;
  owner?: string;
  evidence?: string[];
  reason?: string;
}

function validate(items: Item[]): void {
  for (const item of items) {
    if (!item.id || !item.title) {
      throw new Error("empty required fields");
    }

    if (
      (item.severity === Severity.Critical || item.severity === Severity.High) &&
      item.status === Status.No
    ) {
      throw new Error(`blocking checklist item: ${item.id}`);
    }

    if (item.status === Status.Partial && !item.owner) {
      throw new Error(`partial item requires owner: ${item.id}`);
    }

    if (
      item.status === Status.Yes &&
      (item.severity === Severity.Critical || item.severity === Severity.High) &&
      (!item.evidence || item.evidence.length === 0)
    ) {
      throw new Error(`high/critical item requires evidence: ${item.id}`);
    }

    if (item.status === Status.NA && !item.reason) {
      throw new Error(`N/A requires reason: ${item.id}`);
    }
  }
}

export {};
