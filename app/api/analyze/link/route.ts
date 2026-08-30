import { NextRequest, NextResponse } from "next/server";
import { UrlAnalyzer } from "@/lib/security/url-analyzer";
import { AnalysisStorage } from "@/lib/security/analysis-storage";
import { RateLimiter } from "@/lib/security/rate-limiter";
import { z } from "zod";

const UrlInputSchema = z.object({
  url: z.string().min(1, "URL cannot be empty").max(2048, "URL exceeds 2048 characters limit"),
});

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for") || "127.0.0.1";
    const rateCheck = RateLimiter.check(ip, 30, 60000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        {
          error: "Rate limit exceeded. Please wait before submitting more URLs.",
          resetInMs: rateCheck.resetInMs,
        },
        { status: 429 }
      );
    }

    const body = await req.json();
    const parsed = UrlInputSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid URL payload", details: parsed.error.errors[0]?.message },
        { status: 400 }
      );
    }

    const analysis = await UrlAnalyzer.analyze(parsed.data.url);

    const persistStatus = await AnalysisStorage.saveAnalysis(analysis);
    analysis.persistenceStatus = persistStatus;

    return NextResponse.json({
      success: true,
      analysis,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Internal URL analysis error";
    return NextResponse.json(
      { error: "URL analysis encountered an error.", details: message },
      { status: 500 }
    );
  }
}
