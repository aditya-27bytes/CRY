// Tests fixture: vulnerable TypeScript/Prisma/Vue patterns for v0.4 rules

declare const prisma: any;
declare const id: string;
declare const userContent: string;

export async function prismaRawQueryVulnerable() {
    // Vulnerable: raw query with string interpolation
    return await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = ${id}`);
}

export function vueHtmlVulnerable() {
    // Vulnerable: v-html bound to unsanitized variable
    const template = '<div v-html="userContent"></div>';
    return template;
}
