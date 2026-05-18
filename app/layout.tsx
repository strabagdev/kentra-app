import type { Metadata, Viewport } from "next";
import { PwaRegister } from "./pwa-register";
import "./globals.css";

export const metadata: Metadata = {
  applicationName: "Kentra Vault",
  title: "Kentra Vault",
  description: "Bóveda de contraseñas por usuario y categoría.",
  appleWebApp: {
    capable: true,
    statusBarStyle: "default",
    title: "Kentra Vault",
  },
  formatDetection: {
    telephone: false,
  },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  themeColor: "#1f2933",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="es" className="h-full antialiased">
      <body className="min-h-full flex flex-col">
        <PwaRegister />
        {children}
      </body>
    </html>
  );
}
