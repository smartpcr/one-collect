# Session: 2025-11-25 - Update CLAUDE.md Documentation References

## Context
Updating CLAUDE.md to include references to all documentation sources: design documents in `docs/`, expert guides in `.claude/agents/`, and prompt history tracking in `.claude/prompts/`.

## Prompts and Responses

### Prompt 1: Update CLAUDE.md with documentation context
**User prompt:**
```
modify Claude.md file, make sure all prompts take context from files under docs folder as well as docs under .claude/agents, and remember to keep prompt history following templates under .claude/prompts
```

**Response summary:**
- Analyzed existing CLAUDE.md structure
- Reviewed all documentation files:
  - `docs/one_collect-design.md` - Core library design
  - `docs/record-trace-design.md` - CLI tool design
  - `docs/ruwind-design.md` - Stack unwinding library design
  - `.claude/agents/architecture-expert.md` - Architecture guidance
  - `.claude/agents/design-patterns-expert.md` - Pattern guidance
  - `.claude/agents/testing-expert.md` - Testing guidance
  - `.claude/agents/usage-guide-expert.md` - Usage guidance
- Added new "Documentation Context" section at the top of CLAUDE.md
- Organized references into three categories:
  1. Design Documents (`docs/`)
  2. Expert Guides (`.claude/agents/`)
  3. Prompt History (`.claude/prompts/`)
- Preserved all existing content in CLAUDE.md

**Files modified:**
- `CLAUDE.md`

**Files created:**
- `.claude/prompts/sessions/2025-11-25_update_claude_md.md` (this file)

**Outcome:** Success - CLAUDE.md now includes comprehensive documentation references

## Key Changes

### New Documentation Context Section
Added at the top of CLAUDE.md, providing:
- Clear organization of documentation sources
- Brief descriptions of each document's purpose
- Instructions for prompt history tracking

### Documentation Categories
1. **Design Documents** - Detailed architectural documentation
2. **Expert Guides** - Specialized knowledge for different aspects
3. **Tracing Guidelines** - Logging best practices
4. **Prompt History** - Session and decision tracking

## References

- CLAUDE.md: Main project documentation
- docs/: Design documentation folder
- .claude/agents/: Expert guide files
- .claude/prompts/: Prompt history templates
