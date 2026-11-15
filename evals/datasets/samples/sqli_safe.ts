// Safe: Parameterized query (no SQL injection)

export interface DbClient {
  query: (sql: string, params: unknown[], callback: (err: Error | null, results: unknown[]) => void) => void;
}

export interface UserRequest {
  params: {
    id: string;
  };
}

export interface UserResponse {
  status: (code: number) => UserResponse;
  json: (body: unknown) => void;
}

export function getUserById(req: UserRequest, res: UserResponse, db: DbClient): void {
  const userId = req.params.id;
  // SAFE: Parameterized query prevents SQL injection
  db.query("SELECT * FROM Users WHERE id = ?", [userId], (err, results) => {
    if (err) {
      res.status(500).json({ error: "Internal error" });
    } else {
      res.json(results);
    }
  });
}

export default getUserById;
