import 'server-only';
export function env(key: string): string { const value = process.env[key]; if (!value) throw new Error(`Missing environment variable: ${key}`); return value; }
export function appUrl() { return new URL(env('APP_URL')).origin; }
