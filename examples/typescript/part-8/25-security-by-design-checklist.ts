// Illustrative examples for notes/part-8-practice/25-security-by-design-checklist.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum Severity {
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
  evidence?: string[];
  owner?: string;
  reviewDate?: Date;
  reason?: string;
}

function validate(items: Item[]): void {
  for (const item of items) {
    if (!item.id || !item.title) {
      throw new Error("checklist item has required empty fields");
    }

    if (!item.severity || !item.status) {
      throw new Error(`checklist item has no severity or status: ${item.id}`);
    }

    if (item.severity === Severity.High && item.status === Status.Yes && (!item.evidence || item.evidence.length === 0)) {
      throw new Error(`high severity item marked Yes without evidence: ${item.id}`);
    }

    if (item.severity === Severity.High && item.status === Status.No) {
      throw new Error(`high severity item is No and blocks release: ${item.id}`);
    }

    if (item.status === Status.Partial && !item.owner) {
      throw new Error(`partial item has no owner: ${item.id}`);
    }

    if (item.status === Status.NA && !item.reason) {
      throw new Error(`N/A item requires reason: ${item.id}`);
    }
  }
}

function exportItems(items: Item[]): string {
  validate(items);
  return JSON.stringify(items, null, 2);
}
