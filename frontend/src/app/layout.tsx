import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "CyberGuard // Threat Intelligence SOC Console",
  description: "Next-Generation Machine Learning Security Operations Center & Multi-Vector Threat Detection Platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
