# Publish checklist

1. `SECURITY.md`: replace `<security contact — fill before publishing>` with a real private reporting path; `Cargo.toml`: set `repository` (replace `<owner>`).
2. `LICENSE`/`NOTICE`: set the copyright line (currently "the jams-recovery-kit authors") to the owner.
3. Create the GitHub repository, push `main`, enable Actions, and confirm the `ci` workflow (including the nightly fuzz job) is green.
