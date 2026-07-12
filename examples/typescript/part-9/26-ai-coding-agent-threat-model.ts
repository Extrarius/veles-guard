// Illustrative examples for notes/part-9-ai-coding-security/26-ai-coding-agent-threat-model.md
// Not for production use. Licensed under MIT (see LICENSE-CODE).

enum RiskLevel {
  Low = "Low",
  Medium = "Medium",
  High = "High",
  Critical = "Critical",
}

interface CodingTask {
  id: string;
  title: string;
  filesTouched?: string[];
  toolsUsed?: string[];
  network?: boolean;
  shell?: boolean;
  dependencies?: boolean;
  ciChanges?: boolean;
  secretsSeen?: boolean;
}

function classifyTask(task: CodingTask): RiskLevel {
  if (task.secretsSeen) {
    return RiskLevel.Critical;
  }
  if (task.ciChanges || task.dependencies) {
    return RiskLevel.High;
  }
  if (task.shell || task.network) {
    return RiskLevel.High;
  }
  if ((task.filesTouched?.length ?? 0) > 10) {
    return RiskLevel.Medium;
  }
  return RiskLevel.Low;
}

export {};
