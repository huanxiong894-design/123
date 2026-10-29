# SQL injection: establish control, retrieve only the intended data

## Scope and evidence

Use only on an explicitly authorized challenge route and its current instance. Do not test other hosts, schemas, accounts, or services. Keep the request count low; never submit a value merely because its format looks like a flag.

A quote-related 500 or SQL error is a **signal**, not proof by itself. Preserve a harmless baseline, then use one controlled true/false pair or one carefully chosen syntax probe. Compare the full response (status, stable body text, and output fields). Stop if responses do not provide a reproducible difference or the attempt/request budget is reached.

Prefer an in-band error or a visible `UNION` result over blind extraction. If the response reflects selected fields, use those fields to infer the output slots and align a minimal `UNION SELECT`; avoid a long `ORDER BY` ladder or broad payload dictionary. A generic pattern is:

```sql
' UNION SELECT NULL, database(), NULL-- -
```

Adjust the number and placement of expressions only when the observed query shape supports it. MySQL/MariaDB commonly accept `-- ` or `#` comments; URL-encode reserved characters once and check the actual request in the tool output.

## Minimal schema discovery

When the challenge evidence indicates that the answer is stored in the current database, inspect only that database's schema:

```sql
' UNION SELECT NULL, group_concat(table_name), NULL
  FROM information_schema.tables
  WHERE table_schema = database()-- -
```

Then inspect columns for one evidence-selected table, and query only the relevant field(s) needed for the challenge. Do not dump every schema/table or enumerate user credentials. If an existing row masks a `UNION` row, use a non-matching predicate value only after the response confirms first-row behavior; record why the adjustment is needed.

## Choose the least expensive technique

1. **Error-based:** use a single syntax probe when the application visibly returns database errors. Treat version text as implementation evidence, not an answer.
2. **Boolean-based:** compare one true and one false condition. A repeatable content difference is stronger evidence than status code alone.
3. **UNION/in-band:** infer output slots from the page, then query only the current challenge's relevant schema/data.
4. **Blind/time-based:** use only when in-band methods are unavailable and the challenge/request budget explicitly permits it. First verify one short delay control and one no-delay control; stop if latency is noisy. Avoid character-by-character extraction when a narrower query is possible.

## Common syntax notes

- Numeric context: `1 AND 1=1` versus `1 AND 1=2`.
- Quoted-string context: a paired boolean condition inside the observed quoting context.
- Parenthesized context: infer parentheses from the actual error before adjusting the expression.
- Comment syntax varies by database; `--` commonly requires a trailing space in MySQL-family engines.
- For a blocked character/keyword, change encoding or syntax only after an observed filter difference justifies it; do not spray bypass variants.

## Safety and stopping

- Never use SQLi to alter/delete data, create accounts, write files, run stacked statements, or exfiltrate through DNS/network channels unless the challenge explicitly requires and authorizes that exact action in a disposable lab.
- Do not use public cracking services or external writeups.
- Keep the exact tool output supporting each conclusion. Submit only a directly observed answer once; after rejection, stop.
