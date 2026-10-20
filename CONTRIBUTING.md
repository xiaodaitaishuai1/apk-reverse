# Contributing

This repository is a skill plus the evidence behind it. Two properties keep it maintainable by more
than one person, and both are **enforced by scripts rather than requested in prose**:

- **every claim carries a strength label**, and
- **every structural relationship is checked** — paths resolve, the on-demand inventory matches the
  entry point, documented commands exist, the always-loaded part has not crept.

The checks exist because both properties decay silently. A stale index still reads as complete; a
claim written from expectation reads like a measurement. If you change something and a gate goes red,
the gate is usually right.

## Run the gates before you push

```bash
python check_repo.py && python check_refs.py && python check_routing.py \
  && python check_commands.py && python check_budget.py && python -m pytest -q
```

Nothing above needs a device, a sample APK, or the network. CI runs the same set on Python 3.11–3.14
plus `mypy` and `flake8`, so a green local run is what a green CI run means.

If `flake8`/`mypy` are not installed, that is the one part CI checks that you cannot reproduce
locally; everything else is plain Python.

## What each gate owns

| Gate | Owns | It cannot see |
|---|---|---|
| `check_repo.py` | frontmatter parses, scripts answer `--help`, every referenced path resolves, every reference is reachable, README paths exist, no target identity on the tracked surface | whether a claim is true |
| `check_refs.py` | every section reference reaches a real heading in the file it names | whether the section still says what the link implies |
| `check_routing.py` | `references/routing.md` and `SKILL.md` agree: symptom mirror identical, every reference file named, every script named | semantics — you can name a file in the wrong row |
| `check_commands.py` | every `python scripts/x.py --flag` a document tells a reader to run matches the script's argparse table | commands inside fenced blocks it cannot attribute to a script |
| `check_budget.py` | `SKILL.md` size in lines and tokens, index-row length, long files with a navigable head | whether a new file is load-bearing or merely adjacent |

**A green run proves consistency, not correctness.** It says paths resolve and the inventory is
complete. It does not say a mechanism works, a tool behaves as described on your device, or a fixture
stands in for a real target. Only the strength labels and the evidence record answer those.

## What a change has to keep in step

This is the list that costs a contributor a red CI run if they miss it:

| If you add or change | Also do | Caught by |
|---|---|---|
| a reference file | name it in `references/routing.md`; make it reachable from `SKILL.md` or the README; give it a "load this when" head if it passes 100 lines | `check_routing.py`, `check_repo.py`, `check_budget.py` |
| a script | add a row to the script table in `references/routing.md`; declare its capability in `scripts/capabilities.py` | `check_routing.py`, `check_repo.py` |
| a symptom-index row | mirror it in `routing.md` (the mirror is compared, not generated) | `check_routing.py` |
| a section heading | update every section reference that pointed at the old name | `check_refs.py` |
| a command in a document | keep the flags real — copy them from `--help`, do not retype them | `check_commands.py` |
| `SKILL.md` | watch the budget: it is loaded in full on every activation, index rows included | `check_budget.py` |
| a capability claim | add or update the row in `evidence/capability-matrix.json` **and** the line in `references/evidence-summary.md` | review — no gate compares them |
| a new pitfall | next number, same four headings (`Symptom` / `Root cause` / `Why it is hard to see` / `The rule`) | review |

The last two rows are deliberately unenforced. A gate can check that a file is named; it cannot check
that a claim is honest, which is why those two are the ones a reviewer has to read.

## The label discipline

Every claim in this repository carries one of four labels (`SKILL.md` §Coverage defines them and
`references/coverage-and-limits.md` carries the long form): `observed`, `inferred`, `unverified`,
`unknown`. Two rules matter more than the rest:

- **`observed` requires a command and its output.** "I reasoned it out" is `inferred`; "someone said
  so" is `unverified`; "nobody looked" is `unknown`.
- **A negative result is `absent`, `unknown` or `present but unreadable`, and only the first is a
  finding.** A probe that came back empty because it could not read the input looks identical to one
  that came back empty because the thing is not there. That confusion is *normal* on hardened targets,
  so name the probe's coverage and run a control that must hit before writing anything down as
  "not there".

If you measured something on one version, one device or one ABI, say which. A number without its
scope is the most common way a correct measurement becomes a wrong claim.

## Pull requests

- **Say what you ran.** Paste the command and the output that matters, not a summary of your
  confidence. Report only checks that actually executed; "should pass" is not a result.
- **Label your own claims** in the same four labels. A large change whose assumptions are labelled is
  easier to review than a small one that presents them as findings.
- **Keep the gate output in the PR body** when a gate was the reason for a change. It is the cheapest
  evidence a reviewer can check.
- **Do not treat a green CI run as approval.** It establishes that code runs and paths resolve — not
  that a claim is true, not that a limit is honest, and not that the change belongs here.
- **Prefer a narrow change with a stated boundary** over a broad one with an implied guarantee. Where
  something could not be exercised here, ship the measured half plus an explicitly labelled template
  for the rest, and say what would have to exist for the other half to become `observed`.
- **One variable at a time.** If a result changed, it should be attributable to the one thing you
  changed (`references/long-task-discipline.md` §single-variable discipline).

## Changing the gates themselves

The gates are code and they can be wrong in two directions: blind (a defect they should catch passes)
and noisy (they fail on a clean tree). Both are testable, and this repository has been bitten by both:

- **A limit that cannot fail is decorative.** `check_budget.py` once computed its hard index-row limit
  and reported `warn` on both branches, so an index row could grow without bound while CI stayed
  green. Watch for the shape where a threshold is defined, evaluated and never escalates.
- **A gate that only varies with the runner is not a gate.** `check_budget.py`'s token estimate had a
  guessed constant, so CI (no `tiktoken`) and a developer machine reached different verdicts.
- **The way to find the first class is to inject the defect and require the failure.** Add the case to
  `tests/unit/` so the next person cannot re-break it: `test_budget_measurement.py` pins both
  behaviours above.

When you fix a gate, add the test that would have caught it, and say in the PR which defect the test
was written against.
