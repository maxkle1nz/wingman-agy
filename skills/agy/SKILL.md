---
name: agy
description: Use when work should go to Google Gemini through the local Antigravity app or the Gemini API, via the `agy` CLI. Two lanes. Agent lane (`agy new`/`send`): dispatch an autonomous Antigravity agent (Gemini 4 Hydrogen/Argon, Flash, or Antigravity-hosted Claude) that works in a workspace on the user's plan quota, good for wide reading, large-context scouting, and well-scoped builds you verify afterwards. API lane (`agy ask`/`img`/`tts`/`embed`): one-shot inference with a Gemini API key. Also for reading what Antigravity agents did (`ls`/`show`/`tail`/`ledger`), checking quota, and diagnosing the install (`doctor`). Not for work you must do yourself, and never for applying setup or grants on the user's behalf.
---

# agy: hand work to Gemini through Antigravity

`agy` is a single-file Python CLI (on PATH as `agy`). It drives the local Antigravity
app's language server for agents, and the public Gemini API for one-shot inference.
Run `agy doctor` first when anything looks off; it is read-only and tells you what is
missing and the one-line fix.

## Pick the lane

| You need | Use | Costs |
|---|---|---|
| An agent that reads, runs commands and edits files on its own | `agy new` (then `send`) | the user's Antigravity plan quota |
| One answer, a summary, a second opinion on text you paste | `agy ask` | Gemini API key (free tier or billed) |
| An image / speech / an embedding | `agy img` / `agy tts` / `agy embed` | Gemini API key |
| A video | `agy video --yes` | real money; only on the user's explicit request |

Do not dispatch an agent for a question `agy ask` answers in seconds. Do not use `ask` for
work that needs to read a repo: it sees only what you put in the prompt.

## Agent lane

```sh
agy quota                                   # plan buckets left; check before a big dispatch
agy models                                  # exact --model ids from the live catalog
agy new --yes --model gemini-4-hydrogen-high --title "scout: X" "<prompt>"
agy new --yes --workspace ~/src/repo --keep --max-invocations 60 --model gemini-4-hydrogen-high "<prompt>"
agy send --yes <id> "<follow-up>"           # continue a conversation (full id or a unique 8+ char prefix)
agy show <id> [--steps N]                   # metadata, models that ran, brain artifacts, last steps
agy tail <id> [-n 40] [-f]                  # readable transcript; -f follows live
agy ledger                                  # agy's own conversations: requested vs RAN model, flags
agy ledger keep <id> --reason "..."         # protect from gc;  agy gc  is a dry run unless --yes
```

**Models.** Always pass an exact id from `agy models`. The default (`flash_lite`) and the
tier names `flash`/`pro` run a Flash model, whatever their names suggest. `agy new` checks
the model that really answered: exit 4 means it ran a different model, exit 5 means it
could not verify. Rough guide:
- `gemini-4-hydrogen-high`: strong generalist; handles 90-200k tokens of context well. The
  default choice for scouting, wide reading and scoped coding.
- `gemini-4-argon-*`: Gemini's top model with its own, smaller weekly bucket. Use it for the
  hard or taste-heavy part, not for bulk.
- `gemini-3.8-flash-*`: fast and cheap for simple, mechanical tasks.
- `claude-*-5-5-*` and `gpt-oss-*`: run on Antigravity's own Claude/GPT bucket, not on any
  Claude subscription of the user.

**Workspace.** Without flags the agent runs in a clean sandbox (`~/agy-sandbox`, or
`outside-of-project` when that is missing), not in your cwd. `--workspace PATH` or `--here`
put it in a real project. Prefer a scratch clone or worktree for code: the agent edits
files and runs commands there.

**Flags worth knowing.**
- `--keep` marks the conversation kept, so `agy gc` never deletes it.
- `--max-invocations N` caps model calls. The wingman plugin enforces it; `agy doctor`
  must show wingman OK, or the cap does not exist.

**Unattended runs.** Agents run without stopping at approval prompts only when doctor shows
the permission grants present (6/6). The wingman plugin also auto-continues an agy
conversation after a transport error ("stream idle timeout"), up to 3 times. It does this
only for conversations in agy's ledger, never for the user's own.

### Writing the brief
- **Put long briefs in a file in the agent's workspace** (for example `.agent/BRIEF.md`) and
  keep the prompt short: "Read .agent/BRIEF.md and do Part A. Finish with at most 20 lines:
  commits, test counts, anything left undone."
- **State the rules plainly:**
  - which clone and branch;
  - small commits and no push;
  - what must never be touched;
  - which live commands are allowed.
- **Write every dangerous command in its safe form.** An agent will run what the brief
  shows.
- **Keep instructions operational.** Gemini refuses text that reads like a trick, such as
  "say this code word".

### Knowing it finished
There is no `agy wait` yet.
- Run `agy show <id>`: it prints the transcript path on its last line.
- In the background, poll that file's size about once a minute. Consider the run finished
  when the file has not grown for ~4 minutes.
- Then read the end with `agy tail <id> -n 60`, and the files the agent changed.

### Verify, always
Gemini agents report confident success, and they rate their own work highly.
- Re-run the tests yourself.
- Read the diff (`git -C <clone> log`/`diff`).
- Look at the outputs yourself.
- For big changes, get an independent review before merging.

Treat the agent as a capable but unsupervised contractor.

## API lane

```sh
agy ask "<prompt>"                 # default gemini-3.6-flash; prompt "-" reads stdin
agy ask -m <model> --search "..."  # grounded on Google Search (queries go to stderr)
agy ask --json schema.json "..."   # structured output
agy ask --file doc.pdf "..."       # uploads to Google's Files API, which KEEPS IT 48h: not for sensitive files
agy img "<prompt>" -o out.png      # agy tts "<text>" -o out.wav   # agy embed "<text>"
```

**stdout and stderr.** stdout is only the answer, so it pipes cleanly. Warnings go to
stderr.

**Thinking tokens count against `--max-tokens`** (default 8192). Set the budget too low and
you get an empty answer with `MAX_TOKENS`. That is not a "no".

**The key.** It comes from `GEMINI_API_KEY` or the Keychain item `gemini-api-key`.
- If doctor says it is missing, the USER runs `agy setup --apply` in a terminal.
- Never print a key, put one in a URL, or write one to a file.

**Images without an API key.** Antigravity agents have their own `generate_image` tool,
covered by the plan. Asking an agent for an image needs no key; this is unproven through
`agy new` so far.

## Never
- **Never run `agy setup --apply`, `agy setup --undo`, `agy grants enable` or `agy ledger
  adopt` for the user.** They change the user's Antigravity configuration or agy's ledger. agy
  refuses the first three inside agent environments. Show the user the command and let them run it.
- **Never write under `~/.gemini/antigravity/`, `~/.gemini/config/` or `~/.agy/`.** They are
  live app state and agy's ledger; use agy's commands.
- **Never print the daemon's CSRF token, MCP env values or API keys.** `agy status` and
  `agy doctor` show presence only.
- **Never spend `agy video` or large batches** without the user's explicit request.

## Troubleshooting
- **"daemon not running" (exit 2):** the Antigravity app is closed; ask the user to open
  it.
- **"mid-restart" or a port error:** the daemon is restarting; re-run in a few seconds.
- **Exit 3:** an authentication or token problem; run `agy doctor`.
- **The agent stopped at a permission prompt:** run `agy doctor` and check the grants and
  wingman lines.
- **The agent went quiet after a "stream idle timeout":** wingman retries by itself. After 3
  failures, `agy send --yes <id> "continue from where you stopped"`.
- **Anything else:** `agy doctor --json` for a machine-readable diagnosis; `agy <command>
  --help` documents every flag.
