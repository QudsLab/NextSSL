# Changelog

## [Unreleased] - 2026-02-12-

### System & Workflow [T-6]
- **Prompt Upgrade (Addendum)**:
  - Added strict logging rules for `log/chat` and `log/prompt`.
  - Documented purpose and usage for all `note/` subdirectories (`tasks`, `changes`, `bin`, `code`, `features`, `idea`).
  - Added Pre-flight checks for log directories.

- **Prompt Upgrade**:
  - Completely rewrote `PROMPT.md` to enforce strict document-driven workflow.
  - Established `note/tasks/` as the sole location for task definitions.
  - Established `note/changes/` for atomic change logging.
  - Implemented mandatory pre-flight checklist and output quality gates.
