import type { Metadata } from 'next';
import './globals.css';
import { headers } from 'next/headers';
export const metadata: Metadata={title:'ScopeGrip AI | Workspace Security',description:'Understand and revoke risky Google Workspace app permissions.'};
export default async function RootLayout({children}:{children:React.ReactNode}) { await headers(); return <html lang="en"><body>{children}</body></html>; }
