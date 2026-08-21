/** Subsequence-based fuzzy match: every character of `query`, in order,
 * must appear somewhere in `target` (case-insensitive). Lightweight enough
 * to skip pulling in a matching library for T-7.18's palette. */
export function fuzzyMatch(query: string, target: string): boolean {
  if (query === '') return true
  const q = query.toLowerCase()
  const t = target.toLowerCase()
  let qi = 0
  for (let ti = 0; ti < t.length && qi < q.length; ti++) {
    if (t[ti] === q[qi]) qi++
  }
  return qi === q.length
}
