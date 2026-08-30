import { NextRequest, NextResponse } from "next/server";
import { MessageAnalyzer } from "@/lib/security/message-analyzer";
import { AnalysisStorage } from "@/lib/security/analysis-storage";
import { RateLimiter } from "@/lib/security/rate-limiter";
import { z } from "zod";

const MessageInputSchema = z.object({
  message: z.string().min(1, "Message cannot be empty").max(10000, "Message exceeds 10,000 characters limit"),
});

export async function POST(req: NextRequest) {
  try {
    const ip = req.headers.get("x-forwarded-for") || "127.0.0.1";
    const rateCheck = RateLimiter.check(ip, 30, 60000);
    if (!rateCheck.allowed) {
      return NextResponse.json(
        {
          error: "Rate limit exceeded. Please wait before submitting more messages.",
          resetInMs: rateCheck.resetInMs,
        },
        { status: 429 }
      );
    }

    const body = await req.json();
    const parsed = MessageInputSchema.safeParse(body);

    if (!parsed.success) {
      return NextResponse.json(
        { error: "Invalid message payload", details: parsed.error.errors[0]?.message },
        { status: 400 }
      );
    }

    const analysis = await MessageAnalyzer.analyze(parsed.data.message);

    const persistStatus = await AnalysisStorage.saveAnalysis(analysis);
    analysis.persistenceStatus = persistStatus;

    return NextResponse.json({
      success: true,
      analysis,
    });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : "Internal message analysis error";
    return NextResponse.json(
      { error: "Message analysis encountered an error.", details: message },
      { status: 500 }
    );
  }
}
