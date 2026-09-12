import 'server-only';
import Stripe from 'stripe';
import { env } from '@/lib/env';
export function stripeClient() { return new Stripe(env('STRIPE_SECRET_KEY'),{maxNetworkRetries:2,timeout:20000}); }
