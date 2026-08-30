import { NextRequest, NextResponse } from "next/server";
import { AnalysisStorage } from "@/lib/security/analysis-storage";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const mode = searchParams.get("mode"); // "dashboard" or "list"

    if (mode === "dashboard") {
      const stats = await AnalysisStorage.getDashboardStats();
      return NextResponse.json({ success: true, stats });
    }

    const limit = parseInt(searchParams.get("limit") || "30", 10);
    const { items, dbConnected } = await AnalysisStorage.getRecentAnalyses(limit);

    return NextResponse.json({
      success: true,
      analyses: items,
      dbConnected,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Error fetching analyses";
    return NextResponse.json(
      { error: "Failed to retrieve analyses", details: message },
      { status: 500 }
    );
  }
}
