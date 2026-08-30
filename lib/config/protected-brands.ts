export interface ProtectedBrand {
  name: string;
  category: "banking" | "fintech" | "tech" | "social" | "crypto" | "ecommerce" | "streaming" | "shipping";
  domains: string[]; // Official authoritative domains
  keywords: string[]; // High-affinity keywords often spoofed in subdomains/paths
}

export const PROTECTED_BRANDS: ProtectedBrand[] = [
  {
    name: "PayPal",
    category: "fintech",
    domains: ["paypal.com", "paypal.me"],
    keywords: ["paypal", "paypa1", "pay-pal", "pp-secure", "paypal-service"],
  },
  {
    name: "Apple / iCloud",
    category: "tech",
    domains: ["apple.com", "icloud.com", "appleid.apple.com"],
    keywords: ["apple-id", "icloud-find", "apple-support", "app1e", "appleid-verify"],
  },
  {
    name: "Google",
    category: "tech",
    domains: ["google.com", "accounts.google.com", "gmail.com"],
    keywords: ["google-security", "gmail-login", "g00gle", "google-verify"],
  },
  {
    name: "Microsoft",
    category: "tech",
    domains: ["microsoft.com", "live.com", "login.microsoftonline.com", "office.com"],
    keywords: ["ms-security", "office365-verify", "micros0ft", "outlook-security"],
  },
  {
    name: "Amazon",
    category: "ecommerce",
    domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de"],
    keywords: ["amazon-orders", "amazon-security", "amaz0n", "amzn-delivery"],
  },
  {
    name: "Netflix",
    category: "streaming",
    domains: ["netflix.com"],
    keywords: ["netflix-payment", "netflix-update", "netf1ix", "netflix-billing"],
  },
  {
    name: "State Bank of India (SBI)",
    category: "banking",
    domains: ["sbi.co.in", "onlinesbi.sbi", "onlinesbi.com"],
    keywords: ["onlinesbi", "sbi-kyc", "sbi-rewards", "sbi-card", "sbiyono"],
  },
  {
    name: "HDFC Bank",
    category: "banking",
    domains: ["hdfcbank.com"],
    keywords: ["hdfc-kyc", "hdfc-netbanking", "hdfc-rewards", "hdfcbank-update"],
  },
  {
    name: "ICICI Bank",
    category: "banking",
    domains: ["icicibank.com"],
    keywords: ["icici-netbanking", "icici-kyc", "icici-rewards"],
  },
  {
    name: "Chase Bank",
    category: "banking",
    domains: ["chase.com"],
    keywords: ["chase-online", "chase-verify", "chase-security"],
  },
  {
    name: "Bank of America",
    category: "banking",
    domains: ["bankofamerica.com", "bofa.com"],
    keywords: ["bofa-security", "bankofamerica-login", "bofa-verify"],
  },
  {
    name: "Binance",
    category: "crypto",
    domains: ["binance.com"],
    keywords: ["binance-verify", "binance-login", "binance-security"],
  },
  {
    name: "Coinbase",
    category: "crypto",
    domains: ["coinbase.com"],
    keywords: ["coinbase-verify", "coinbase-support", "coinbase-login"],
  },
  {
    name: "Meta / WhatsApp / Instagram",
    category: "social",
    domains: ["facebook.com", "instagram.com", "whatsapp.com", "meta.com"],
    keywords: ["whatsapp-web-login", "instagram-verify", "facebook-security-badge"],
  },
  {
    name: "DHL / FedEx / Postal Service",
    category: "shipping",
    domains: ["dhl.com", "fedex.com", "usps.com", "indiapost.gov.in"],
    keywords: ["dhl-track", "fedex-package-reschedule", "usps-redelivery", "indiapost-tracking"],
  },
];
