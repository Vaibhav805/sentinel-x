import "./globals.css";

export const metadata = {
  title: "Sentinel-X — XDP Firewall Dashboard",
  description: "Real-time eBPF network observability",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#020817] text-slate-100 antialiased">{children}</body>
    </html>
  );
}