# Prompt History Tracking

This directory tracks important prompts and responses for future reference and learning.

## Purpose

- Document successful prompt patterns that led to good results
- Track decision-making rationale for architectural and design choices
- Build a knowledge base of effective interactions with AI coding assistants
- Preserve context for future development sessions

## Structure

```
.claude/prompts/
├── README.md                    # This file
├── sessions/                    # Individual session logs
│   └── YYYY-MM-DD_session.md
├── patterns/                    # Reusable prompt patterns
│   ├── architecture.md
│   ├── debugging.md
│   ├── refactoring.md
│   └── testing.md
└── decisions/                   # Major technical decisions
    └── YYYY-MM-DD_decision.md
```

## Usage

### Recording Sessions

Create a new session file when starting significant work:

```bash
# Create new session file
date=$(date +%Y-%m-%d)
touch .claude/prompts/sessions/${date}_session.md
```

Session file format:
```markdown
# Session: YYYY-MM-DD - Brief Description

## Context
What we're trying to accomplish

## Prompts and Responses

### Prompt 1: [Brief description]
**User prompt:**
```
[The actual prompt text]
```

**Response summary:**
- Key points from response
- Files modified
- Insights gained

**Outcome:** Success/Partial/Failed

---

### Prompt 2: [Brief description]
...
```

### Recording Patterns

When you discover an effective prompt pattern:

```markdown
# Pattern: [Name]

## Use Case
When to use this pattern

## Template
```
[Prompt template with placeholders]
```

## Example
```
[Concrete example]
```

## Tips
- Tip 1
- Tip 2
```

### Recording Decisions

For major technical decisions:

```markdown
# Decision: [Brief title]

**Date:** YYYY-MM-DD
**Context:** What problem are we solving?
**Decision:** What did we decide?

## Options Considered
1. Option A
   - Pros: ...
   - Cons: ...

2. Option B
   - Pros: ...
   - Cons: ...

## Rationale
Why we chose this option

## Consequences
- Positive consequence 1
- Potential challenge 1

## References
- Links to relevant code
- Related decisions
- External references
```

## Best Practices

1. **Be Specific**: Include exact prompts, not summaries
2. **Record Context**: Note what you were trying to achieve
3. **Track Outcomes**: Document what worked and what didn't
4. **Extract Patterns**: When a prompt works well multiple times, create a pattern
5. **Link Related Items**: Reference related sessions, patterns, and decisions
6. **Regular Review**: Periodically review to identify trends and improvements

## Example Workflow

```bash
# Starting new feature work
echo "# Session: $(date +%Y-%m-%d) - Add new export format" > \
  .claude/prompts/sessions/$(date +%Y-%m-%d)_export_format.md

# During work: copy effective prompts into session file
# After major decision: document in decisions/
# After completing work: extract reusable patterns
```

## Integration with Git

Add to `.gitignore` if prompts contain sensitive information:
```gitignore
.claude/prompts/sessions/
```

Keep patterns and decisions in version control:
```gitignore
!.claude/prompts/patterns/
!.claude/prompts/decisions/
```

## Maintenance

- Archive old sessions after 6 months
- Review and update patterns quarterly
- Consolidate related decisions into architecture documents
