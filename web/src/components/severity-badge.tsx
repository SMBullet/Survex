import { Badge } from "@/components/ui/badge";

const colors: Record<string, string> = {
  critical: "bg-red-700 text-white hover:bg-red-700",
  high: "bg-orange-600 text-white hover:bg-orange-600",
  medium: "bg-yellow-500 text-black hover:bg-yellow-500",
  low: "bg-blue-500 text-white hover:bg-blue-500",
  info: "bg-slate-500 text-white hover:bg-slate-500",
  "": "bg-muted text-muted-foreground",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = colors[severity.toLowerCase()] ?? colors[""];
  return <Badge className={cls}>{severity || "—"}</Badge>;
}
