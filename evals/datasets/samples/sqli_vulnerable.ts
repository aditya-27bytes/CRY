// Vulnerable: SQL Injection via string concatenation (Juice Shop style)

export interface DbClient {
  query: (sql: string, callback: (err: Error | null, results: unknown[]) => void) => void;
}

export interface SearchRequest {
  query: {
    q?: string;
  };
}

export interface SearchResponse {
  status: (code: number) => SearchResponse;
  json: (body: unknown) => void;
}

export function searchProducts(req: SearchRequest, res: SearchResponse, db: DbClient): void {
  const searchTerm = req.query.q ?? "";
  // VULNERABLE: Direct concatenation of user input into SQL
  const query = "SELECT * FROM Products WHERE name LIKE '%" + searchTerm + "%'";
  db.query(query, (err, results) => {
    if (err) {
      res.status(500).json({ error: "Internal error" });
    } else {
      res.json(results);
    }
  });
}

export default searchProducts;
