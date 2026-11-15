// Safe: Mock token and headers strictly for test fixtures and unit tests.
// Uses environment variable fallback and typed interfaces.

declare const process: {
  env: Record<string, string | undefined>;
};

export interface MockHeaders {
  Authorization: string;
  "Content-Type": string;
}

export const MOCK_AUTH_TOKEN: string =
  process.env.TEST_MOCK_TOKEN ?? "mock-test-token";

export function getMockHeaders(): MockHeaders {
  return {
    Authorization: `Bearer ${MOCK_AUTH_TOKEN}`,
    "Content-Type": "application/json",
  };
}

