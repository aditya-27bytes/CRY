// Vulnerable: Unvalidated URL redirect from query parameter (CWE-601)

export interface RequestLike {
  query: Record<string, string | undefined>;
}

export interface ResponseLike {
  redirect: (url: string) => void;
  status: (code: number) => ResponseLike;
  send: (body: string) => void;
}

export function handleRedirect(req: RequestLike, res: ResponseLike): void {
  // VULNERABLE: Takes redirect target directly from user input without validation
  const targetUrl = req.query.url ?? "/";
  res.redirect(targetUrl);
}

export default handleRedirect;
