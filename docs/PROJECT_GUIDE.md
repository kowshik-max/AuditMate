# AuditMate project guide

1. Login: the app checks a password hash in the users table.
2. Dashboard: counts controls, implemented controls, open gaps, evidence awaiting review, unfinished tasks and overdue tasks from SQL queries.
3. Security Controls: create and search controls; controls are linked to evidence, gaps and risks.
4. Evidence: add evidence metadata, then upload a restricted file; downloads require login.
5. Compliance Gaps: track missing or incomplete controls, risk, owner, due date and resolution notes.
6. Risk Register: likelihood and impact are scored from 1 to 5; score = likelihood × impact. The rating bands are a simple custom heuristic (High >=15, Medium >=8, otherwise Low), not an official standard.
7. Remediation Tasks: assign work linked to gaps and track status.
8. Audit Activity: review application actions recorded by the server.
9. Reports: download control summaries as CSV or PDF.
10. Settings: workspace label preference is session-only in this version.

Use synthetic data only. Seed controls are examples, not actual audit evidence or official ISO/IEC 27001 text.
