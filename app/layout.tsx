import React from "react";

export const metadata = {
  title: "Verify Me - Trust Layer MVP",
  description: "Media authenticity MVP: sign hashes and verify provenance.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ margin: 0 }}>{children}</body>
    </html>
  );
}
