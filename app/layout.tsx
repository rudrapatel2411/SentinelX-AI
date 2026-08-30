import type { Metadata } from "next";
import { Navbar } from "@/components/layout/Navbar";
import { Footer } from "@/components/layout/Footer";
import "./globals.css";

export const metadata: Metadata = {
  title: "SentinelX AI — Protecting Every Click, Every Download, Every Payment",
  description:
    "Production-grade cybersecurity assistant analyzing files, messages, and links using deterministic security rules, threat intelligence, and AI explanation.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen flex flex-col bg-[#060911] text-slate-100 selection:bg-cyan-500 selection:text-slate-950 font-sans antialiased">
        <Navbar />
        <main className="flex-1 cyber-gradient-bg">{children}</main>
        <Footer />
      </body>
    </html>
  );
}
