import { NextRequest, NextResponse } from "next/server";
import { AnalysisStorage } from "@/lib/security/analysis-storage";

export async function GET(
  _req: NextRequest,
  { params }: { params: { id: string } }
) {
  try {
    const id = params.id;
    if (!id) {
      return NextResponse.json({ error: "Missing analysis ID" }, { status: 400 });
    }

    const analysis = await AnalysisStorage.getAnalysisById(id);
    if (!analysis) {
      return NextResponse.json({ error: "Analysis record not found" }, { status: 404 });
    }

    return NextResponse.json({ success: true, analysis });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Error retrieving record";
    return NextResponse.json(
      { error: "Failed to retrieve analysis details", details: message },
      { status: 500 }
    );
  }
}
