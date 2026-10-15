import "./globals.css";

export const metadata = {
  title: "AegisDroid HIDS | Autonomous Android Cyber-Forensics & ML Triage",
  description: "Cascaded Hybrid Android Intrusion Detection System integrating 215-D static bytecode, 470-D dynamic Linux syscalls, VirusTotal v3, and What-If counterfactual remediation.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body suppressHydrationWarning>{children}</body>
    </html>
  );
}
