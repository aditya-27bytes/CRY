// Tests fixture: safe TypeScript/Prisma/Vue patterns for v0.4 rules

declare const prisma: any;
declare const id: string;
declare const userContent: string;
declare const DOMPurify: any;

export async function prismaRawQuerySafe() {
    // Safe: Prisma parameterized tagged template literal
    return await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
}

export function vueHtmlSafe() {
    // Safe: v-html sanitized with DOMPurify
    const template = '<div v-html="DOMPurify.sanitize(userContent)"></div>';
    return template;
}
