# Falcon Traders
Responsive coal supply transaction dashboard. Vehicle entries, payment status, slips, and monthly summaries are stored in Railway PostgreSQL and shared across devices. Editor changes require a server-validated password session. Existing browser-only records can be imported from their original device after signing in, while the shared database is empty.

Set `DATABASE_URL`, `EDIT_PASSWORD`, and `SESSION_SECRET` in the service environment. The application will not start without them.
