import { NextRequest, NextResponse } from "next/server";
import { FileScanner } from "@/lib/security/file-scanner";
import { AnalysisStorage } from "@/lib/security/analysis-storage";
import { RateLimiter } from "@/lib/security/rate-limiter";

export const maxDuration = 30; // Max 30 seconds for analysis

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for") || "127.0.0.1";
    const rateCheck = RateLimiter.check(ip, 20, 60000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        {
          error: "Rate limit exceeded. Please wait before submitting more files.",
          resetInMs: rateCheck.resetInMs,
        },
        { status: 429 }
      );
    }

    const formData = await req.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return NextResponse.json(
        { error: "No file provided in request. Use 'file' field in multipart/form-data." },
        { status: 400 }
      );
    }

    // 50MB Size limit
    const MAX_SIZE = 50 * 1024 * 1024;
    if (file.size > MAX_SIZE) {
      return NextResponse.json(
        { error: "File exceeds 50MB maximum upload limit." },
        { status: 413 }
      );
    }

    const arrayBuffer = await file.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Sanitize filename to prevent directory traversal
    const sanitizedFilename = file.name.replace(/[/\\?%*:|"<>]/g, "_").slice(0, 150);

    // Run full security analysis pipeline
    const analysis = await FileScanner.scan(buffer, sanitizedFilename);

    // Persist result
    const persistStatus = await AnalysisStorage.saveAnalysis(analysis);
    analysis.persistenceStatus = persistStatus;

    return NextResponse.json({
      success: true,
      analysis,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Internal file scanning error";
    return NextResponse.json(
      { error: "File analysis encountered an error.", details: message },
      { status: 500 }
    );
  }
}
