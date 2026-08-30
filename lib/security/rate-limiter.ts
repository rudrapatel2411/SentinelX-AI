/**
 * Sliding Window In-Memory Rate Limiter
 * Suitable for local development and single-instance deployments.
 * Note: For horizontally scaled production clusters, replace with Redis/Upstash backend.
 */
interface RateLimitRecord {
  timestamps: number[];
}

export class RateLimiter {
  private static store = new Map<string, RateLimitRecord>();
  private static lastCleanup = Date.now();

  /**
   * Checks if an IP or client identifier has exceeded rate limits.
   * @param identifier Client IP address or session identifier
   * @param maxRequests Maximum allowed requests per window (default: 30)
   * @param windowMs Time window in milliseconds (default: 60,000ms = 1 minute)
   */
  public static check(
    identifier: string,
    maxRequests = 30,
    windowMs = 60000
  ): { allowed: boolean; remaining: number; resetInMs: number } {
    const now = Date.now();

    // Periodic cleanup of stale keys every 5 minutes
    if (now - this.lastCleanup > 300000) {
      this.cleanup(windowMs);
      this.lastCleanup = now;
    }

    let record = this.store.get(identifier);
    if (!record) {
      record = { timestamps: [] };
      this.store.set(identifier, record);
    }

    // Filter timestamps within the current sliding window
    record.timestamps = record.timestamps.filter((ts) => now - ts < windowMs);

    if (record.timestamps.length >= maxRequests) {
      const oldest = record.timestamps[0];
      const resetInMs = Math.max(0, windowMs - (now - oldest));
      return {
        allowed: false,
        remaining: 0,
        resetInMs,
      };
    }

    // Record this request
    record.timestamps.push(now);
    return {
      allowed: true,
      remaining: maxRequests - record.timestamps.length,
      resetInMs: windowMs,
    };
  }

  private static cleanup(windowMs: number): void {
    const now = Date.now();
    for (const [key, record] of this.store.entries()) {
      record.timestamps = record.timestamps.filter((ts) => now - ts < windowMs);
      if (record.timestamps.length === 0) {
        this.store.delete(key);
      }
    }
  }
}
