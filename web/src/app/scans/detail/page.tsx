"use client";

// Static route: /scans/detail?id=<scan-uuid>
// useSearchParams requires Suspense when used with output: 'export'.

import { Suspense } from "react";
import ScanDetailClient from "./scan-detail-client";

export default function ScanDetailPage() {
  return (
    <Suspense>
      <ScanDetailClient />
    </Suspense>
  );
}
