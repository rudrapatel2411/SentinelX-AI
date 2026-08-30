import { prisma, isDatabaseAvailable } from "@/lib/db/prisma";
import { CommonAnalysisResult, SecurityIndicator, ThreatIntelSourceResult, RiskFactorBreakdown } from "@/lib/types/security";

export interface DashboardStats {
  total: number;
  safe: number;
  suspicious: number;
  dangerous: number;
  recentAnalyses: CommonAnalysisResult[];
  categoryBreakdown: { category: string; count: number }[];
  isDatabaseConnected: boolean;
}

export class AnalysisStorage {
  /**
   * Persists an analysis result into SQLite/PostgreSQL via Prisma.
   * If DB is offline, returns "DATABASE_OFFLINE" without crashing.
   */
  public static async saveAnalysis(
    result: CommonAnalysisResult
  ): Promise<"SAVED" | "DATABASE_OFFLINE"> {
    try {
      const dbConnected = await isDatabaseAvailable();
      if (!dbConnected) {
        return "DATABASE_OFFLINE";
      }

      await prisma.analysis.create({
        data: {
          id: result.id,
          type: result.type,
          target: result.target,
          riskScore: result.riskScore,
          classification: result.classification,
          confidence: result.confidence,
          confidenceLabel: result.confidenceLabel,
          aiSummary: result.aiExplanation.summary,
          aiThreatCategory: result.aiExplanation.threatCategory,
          aiReasons: JSON.stringify(result.aiExplanation.reasons || []),
          aiRecommendedAction: result.aiExplanation.recommendedAction,
          aiWritingLikelihood: result.aiExplanation.aiWritingLikelihood,
          aiAvailable: result.aiExplanation.available,
          recommendations: JSON.stringify(result.recommendations || []),
          metadata: JSON.stringify(result.metadata || {}),
          createdAt: new Date(result.createdAt),
          indicators: {
            create: result.indicators.map((ind) => ({
              indicatorId: ind.id,
              title: ind.title,
              description: ind.description,
              severity: ind.severity,
              weight: ind.weight,
              confidence: ind.confidence,
              category: ind.category,
              source: ind.source,
              mitigating: ind.mitigating || false,
            })),
          },
          threatIntelResults: {
            create: result.threatIntel.map((intel) => ({
              sourceName: intel.name,
              status: intel.status,
              details: intel.details || null,
              positives: intel.positives ?? null,
              total: intel.total ?? null,
              detectedThreats: JSON.stringify(intel.detectedThreats || []),
            })),
          },
        },
      });

      return "SAVED";
    } catch (err) {
      console.error("Storage error:", err);
      return "DATABASE_OFFLINE";
    }
  }

  /**
   * Retrieves recent analyses
   */
  public static async getRecentAnalyses(limit = 20): Promise<{ items: CommonAnalysisResult[]; dbConnected: boolean }> {
    try {
      const dbConnected = await isDatabaseAvailable();
      if (!dbConnected) {
        return { items: [], dbConnected: false };
      }

      const records = await prisma.analysis.findMany({
        take: limit,
        orderBy: { createdAt: "desc" },
        include: {
          indicators: true,
          threatIntelResults: true,
        },
      });

      const items: CommonAnalysisResult[] = records.map((r) => this.mapRecordToResult(r));
      return { items, dbConnected: true };
    } catch {
      return { items: [], dbConnected: false };
    }
  }

  /**
   * Retrieves a single analysis by its ID (e.g. SX-20260830-8F31A2)
   */
  public static async getAnalysisById(id: string): Promise<CommonAnalysisResult | null> {
    try {
      const dbConnected = await isDatabaseAvailable();
      if (!dbConnected) return null;

      const record = await prisma.analysis.findUnique({
        where: { id },
        include: {
          indicators: true,
          threatIntelResults: true,
        },
      });

      if (!record) return null;
      return this.mapRecordToResult(record);
    } catch {
      return null;
    }
  }

  /**
   * Calculates dashboard summary metrics from actual database records
   */
  public static async getDashboardStats(): Promise<DashboardStats> {
    try {
      const dbConnected = await isDatabaseAvailable();
      if (!dbConnected) {
        return {
          total: 0,
          safe: 0,
          suspicious: 0,
          dangerous: 0,
          recentAnalyses: [],
          categoryBreakdown: [],
          isDatabaseConnected: false,
        };
      }

      const [total, safe, suspicious, dangerous, recent] = await Promise.all([
        prisma.analysis.count(),
        prisma.analysis.count({ where: { classification: "SAFE" } }),
        prisma.analysis.count({ where: { classification: "SUSPICIOUS" } }),
        prisma.analysis.count({ where: { classification: "DANGEROUS" } }),
        prisma.analysis.findMany({
          take: 8,
          orderBy: { createdAt: "desc" },
          include: { indicators: true, threatIntelResults: true },
        }),
      ]);

      // Category breakdown from indicators
      const indicators = await prisma.threatIndicator.groupBy({
        by: ["category"],
        _count: { category: true },
        where: { mitigating: false },
      });

      const categoryBreakdown = indicators.map((g) => ({
        category: g.category,
        count: g._count.category,
      }));

      return {
        total,
        safe,
        suspicious,
        dangerous,
        recentAnalyses: recent.map((r) => this.mapRecordToResult(r)),
        categoryBreakdown,
        isDatabaseConnected: true,
      };
    } catch {
      return {
        total: 0,
        safe: 0,
        suspicious: 0,
        dangerous: 0,
        recentAnalyses: [],
        categoryBreakdown: [],
        isDatabaseConnected: false,
      };
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  private static mapRecordToResult(record: any): CommonAnalysisResult {
    const indicators: SecurityIndicator[] = (record.indicators || []).map((i: any) => ({
      id: i.indicatorId,
      title: i.title,
      description: i.description,
      severity: i.severity as any,
      weight: i.weight,
      confidence: i.confidence,
      category: i.category as any,
      source: i.source,
      mitigating: i.mitigating,
    }));

    const threatIntel: ThreatIntelSourceResult[] = (record.threatIntelResults || []).map((t: any) => {
      let detectedThreats: string[] = [];
      try {
        detectedThreats = t.detectedThreats ? JSON.parse(t.detectedThreats) : [];
      } catch {
        detectedThreats = [];
      }
      return {
        name: t.sourceName,
        status: t.status as any,
        details: t.details || undefined,
        positives: t.positives ?? undefined,
        total: t.total ?? undefined,
        detectedThreats,
      };
    });

    let aiReasons: string[] = [];
    try {
      aiReasons = record.aiReasons ? JSON.parse(record.aiReasons) : [];
    } catch {
      aiReasons = [];
    }

    let recommendations: string[] = [];
    try {
      recommendations = record.recommendations ? JSON.parse(record.recommendations) : [];
    } catch {
      recommendations = [];
    }

    let metadata: Record<string, unknown> = {};
    try {
      metadata = record.metadata ? JSON.parse(record.metadata) : {};
    } catch {
      metadata = {};
    }

    const riskFactors: RiskFactorBreakdown[] = [];

    return {
      id: record.id,
      type: record.type as "file" | "message" | "url",
      target: record.target,
      riskScore: record.riskScore,
      classification: record.classification as any,
      confidence: record.confidence,
      confidenceLabel: record.confidenceLabel as any,
      indicators,
      riskFactors,
      threatIntel,
      aiExplanation: {
        summary: record.aiSummary || "",
        threatCategory: record.aiThreatCategory || "",
        reasons: aiReasons,
        recommendedAction: record.aiRecommendedAction || "",
        aiWritingLikelihood: record.aiWritingLikelihood,
        available: record.aiAvailable,
      },
      recommendations,
      createdAt: record.createdAt.toISOString(),
      metadata,
      persistenceStatus: "SAVED",
    };
  }
}
