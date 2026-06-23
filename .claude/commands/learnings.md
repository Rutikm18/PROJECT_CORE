---
description: Append new concepts/topics from this conversation to LEARNINGS.md
---

Update `LEARNINGS.md` at the project root with anything from this conversation that isn't already documented there.

Rules:
- Scan the current conversation for new technical concepts, libraries, patterns, or design decisions that were actually implemented (not just discussed/rejected).
- For each new one, check if it's already in LEARNINGS.md (by heading/topic name) — skip if it is.
- For each genuinely new one, append an entry using this exact format:

  ### <Topic name>
  **What:** <one or two sentences, plain definition>
  **Why:** <one or two sentences — why THIS project needed it, tied to the actual bug/feature, not generic praise>

- Keep entries short — this is a glossary/changelog, not a tutorial. No code blocks unless a single line is essential.
- Group under a `## <date>` heading for today (use the date from context, don't ask). If today's date heading already exists, append under it instead of creating a duplicate.
- Order entries within a date in the order they came up.
- Do not rewrite or reformat existing entries. Only append.
- If nothing new came up this conversation, say so briefly and don't touch the file.
