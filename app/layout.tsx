import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Kentra Vault",
  description: "Bóveda de contraseñas por usuario y categoría.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
