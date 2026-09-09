# Defects found during the workstation-plugin build, 2026-09-08

Recorded at the PersonaCore side's request, because none of these were visible from there and
several were invisible from here too until something unrelated disturbed them. Each entry says how
it was found, because the finding method is the reusable part.

All are fixed. The point of this file is that they are not rediscovered, and that the conditions
which hid them are recognised next time.

---

## 1. A deadlock whose ceiling scaled with the machine

`mcp_host/mcp_client.py` read each plugin's stdout with `run_in_executor(None, readline)` in a
loop. That parks **one worker of the event loop's default `ThreadPoolExecutor` for the entire life
of that plugin**. The pool is `min(32, cpu_count + 4)` — 12 on an 8-core machine.

Eleven bundled plugins fitted with one spare. The twelfth took the last worker; its own
`initialize` then needed a worker to write stdin, that write queued behind twelve reads that never
return, and startup deadlocked. The 30 s request timeout did not fire because the write was
*queued*, not running, and `close()` then waited on a task stuck in an uncancellable executor call.

**Why it hid:** it required twelve plugins to exist simultaneously. Every subtask that added one
tested with fewer. **The ceiling is a function of `cpu_count`** — a 4-core CI box has 8 workers and
would have deadlocked at eight plugins, on a machine nobody was watching.

**Fix:** a blocking read that never returns is not a unit of work, it is a dedicated thread wearing
a borrowed one. The reader owns a daemon thread and hands lines back via `call_soon_threadsafe`;
`close()` stops it by closing the pipe rather than awaiting an uncancellable task.

**Found by:** merging the twelfth plugin. Not by any test.

---

## 2. Plugin signature validity depended on the checkout's git configuration

The signature digest covered raw bytes. This repo has `core.autocrlf=true` and had no
`.gitattributes`, so the shipped plugins were signed over CRLF. A plugin authored in a worktree as
LF verified there and turned `invalid` the moment the same content reached the main checkout as
CRLF — identical `signature.sig`, different bytes hashed.

**A fresh clone with `core.autocrlf=false` would have invalidated every shipped plugin**, and
`plugins.allow_unsigned` defaults to false. The product would have shipped with no working plugins
and an error mentioning nothing about line endings.

**Why it hid:** it passes every test on the machine that authored the plugin. It only appears when
the signing checkout and the verifying checkout disagree.

**Fix:** the digest normalises newlines for Python source before hashing, so validity is a property
of the plugin rather than of the checkout. Safe for source specifically because CPython's tokenizer
performs the same translation in the source decoder before compiling — every member of a collision
class produces an identical code object, which is asserted by compiling all three forms and
comparing `co_consts`. **That argument does not carry to non-Python files**, so normalisation is
scoped by suffix and a test fails if anyone widens it.

**Found by:** a merge that broke. Not by any test.

---

## 3. Signatures covered `.py` only, while Python imports more than that

`_resolve_module_paths` hashed `__init__.py` and `__main__.py` for a package plugin — so any other
submodule executed uncovered. Three families consolidated into a single file to work around it.

Worse: `.py` is not the importable set. A planted `.pyd`, `.so` or sourceless `.pyc` is loaded
natively by the import machinery and was hashed by nothing. That is **arbitrary native code
execution with `verify()` still returning `valid`**.

Separately, the signing message concatenated digests with no filenames, so any rename or directory
move preserving sort order left it byte-identical and the signature valid.

**Fix:** the covered set is every importable file in the package tree; each file contributes a
fixed 64 bytes, 32 of name and 32 of content, so framing is unambiguous; the message carries a
scheme tag so an old signature fails cleanly rather than being reinterpreted. `__pycache__` is
excluded because CPython rewrites it on first import — the residual risk of a forged cache entry is
recorded in place, and its mitigation belongs in the supervisor.

**Found by:** chasing defect 2.

---

## 4. Two shipped tools were broken, and their tests hid it

`agent.toast` called `ToastPresenter.present(...)`, which does not exist — the real API is a
synchronous `show()`. `agent.execute_local` did `json.dumps` on a `ToolResultImpl` dataclass with
no `default=`, so **every successful call raised `TypeError` and returned `isError: true`**.

**Why they hid:** both tests mocked the collaborators with permissive mocks that accept any method
name and any payload. A `MagicMock` will happily answer `.present()`.

**Fix:** the fakes now implement the real signatures, so a reintroduced `.present()` raises. The
lesson generalises — a fake that accepts anything tests nothing about the boundary it stands in for.

---

## 5. A §5.6 token could splice across two JSON fields

`host._conform_text_block` stripped the *serialised* envelope, and the angle-pipe pattern is the
only one with a wildcard body. So `{"stdout": "tail <|im_", "stderr": "x|> head"}` rendered to a
string where the match spanned the JSON structure between the two fields, and the substitution
deleted that structure — leaving text that was no longer an envelope. Any tool controlling two
output streams could do this deliberately; a shell command is exactly that.

**Fix:** the envelope is decoded, stripped per value, and rebuilt, so the splice is impossible for
every family rather than each defending itself.

---

## 6. Three tests corrupted tracked source, and one contaminated the whole run

A fixture rewrote `plugins/hello_world/signature.sig` in place, and two tests appended `# tampered`
to that plugin's `__init__.py` and `__main__.py`, restoring in a `finally` that does not run when a
session is killed. A developer's working tree — and this one, mid-diagnosis — ended up with a
plugin verifying `invalid` from leftover state.

Worse, the fixture was **session-scoped**, so from its first use the unsigned canary verified
`valid` instead of `unsigned` for the remainder of the run: invisible cross-test contamination.

**Fix:** all three operate on a `tmp_path` copy, and a test asserts a suite run never modifies a
tracked plugin signature.

**Why it matters beyond tidiness:** half-restored state made defect 1 look like a code bug for
longer than it should have.

---

## 7. The signer could mis-sign silently

Signing labels come from `find_spec`. In a worktree the editable install resolves to the main
checkout, so a new package was unresolvable and the signer quietly fell back to a different label
scheme — producing a signature the post-merge verifier rejects. It was caught by reading the
signer's output, which the next person would not do.

**Fix:** the signer refuses when a `-m` entry falls back to the directory scan, naming the module,
with an opt-in flag for genuinely out-of-tree plugins. Refusing beats warning here because the
signer's own verify step resolves the same wrong way, so it can never catch itself.

---

## The pattern worth keeping

Four of these were pre-existing. Not one was found by writing a test for the thing it broke — they
were found by **merging**, by **combining components that had only been tested apart**, and by
**one component transcribing another's code and then questioning it**.

Two conditions hid most of them:

- **Permissive test doubles.** A mock that accepts any method or any payload asserts nothing about
  the boundary it replaces. Fakes implementing the real signature caught defect 4 immediately.
- **Testing in isolation.** Defects 1, 2 and 6 are all invisible until two things that were built
  separately are put in the same tree at the same time.
