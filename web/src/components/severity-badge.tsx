import { Badge } from "@/components/ui/badge";

const cfg: Record<string, { cls: string; dot: string }> = {
  critical: { cls: "bg-red-500/15 text-red-400 border border-red-500/30",    dot: "bg-red-400" },
  high:     { cls: "bg-orange-500/15 text-orange-400 border border-orange-500/30", dot: "bg-orange-400" },
  medium:   { cls: "bg-yellow-500/15 text-yellow-400 border border-yellow-500/30", dot: "bg-yellow-400" },
  low:      { cls: "bg-blue-500/15 text-blue-400 border border-blue-500/30",  dot: "bg-blue-400" },
  info:     { cls: "bg-zinc-500/15 text-zinc-400 border border-zinc-500/30",  dot: "bg-zinc-500" },
  "":       { cls: "bg-zinc-800/50 text-zinc-600 border border-zinc-700/30",  dot: "bg-zinc-700" },
};

export function SeverityBadge({ severity }: { severity: string }) {
  const key  = severity.toLowerCase();
  const { cls, dot } = cfg[key] ?? cfg[""];
  return (
    <Badge className={`${cls} flex items-center gap-1.5 font-mono text-[11px] font-semibold uppercase tracking-wider`}>
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${dot}`} />
      {severity || "—"}
    </Badge>
  );
}
