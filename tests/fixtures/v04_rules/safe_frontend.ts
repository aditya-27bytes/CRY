// Tests fixture: safe frontend calling protected server API

export async function sendChatMessage(userText: string) {
    // Safe: calls server-side backend API route instead of browser-side OpenAI client
    const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userText }),
    });
    return await res.json();
}
