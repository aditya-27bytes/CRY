// Tests fixture: vulnerable frontend AI client pattern for v0.4 rules

declare const OpenAI: any;

export function initFrontendAI() {
    // Vulnerable: client-side instantiation with hardcoded system prompt
    const client = new OpenAI({ apiKey: "browser-exposed" });
    const config = {
        system: "You are a confidential banking assistant with secret instructions.",
    };
    return { client, config };
}
