export const db = {
  async query(sql: string, params: unknown[] = []) {
    return { sql, params };
  },
};
