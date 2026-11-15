// Vulnerable: Hardcoded Stripe live secret key in config

export const STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";

export interface StripeChargeOptions {
  amount: number;
  currency: string;
  source: string;
}

export interface StripeClient {
  charges: {
    create: (options: StripeChargeOptions) => Promise<unknown>;
  };
}

export async function createCharge(
  client: StripeClient,
  amount: number,
  currency: string,
  source: string
): Promise<unknown> {
  return client.charges.create({
    amount,
    currency,
    source,
  });
}
