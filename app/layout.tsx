import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Phishing URL Analyzer | Fayyad Dahweesh",
  description:
    "A defensive cybersecurity tool that analyzes URL structure and checks existing VirusTotal threat-intelligence reports.",
  keywords: [
    "phishing analysis",
    "URL analyzer",
    "cybersecurity",
    "threat intelligence",
    "VirusTotal",
    "Fayyad Dahweesh",
  ],
  authors: [{ name: "Fayyad Dahweesh" }],
  creator: "Fayyad Dahweesh",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased`}
      >
        {children}
      </body>
    </html>
  );
}