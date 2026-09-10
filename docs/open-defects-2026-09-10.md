# Open defects, written down before a reboot — 2026-09-10

The owner joined a workstation to PersonaCore successfully tonight. **Enrolment works end
to end on a real machine.** He got there by hitting the first defect below and working
around it, which is the thing the test suite could not do.

Main is `974a03a`, pushed. Released: `v0.1.0-alpha.14`.

---

## A. A listening socket outlives the thing serving on it

**How it showed.** The enabled checkbox was ticked; Join refused with *"The endpoint is
not running, so PersonaCore has nothing to push the token to."* He switched the endpoint
off, switched it on again, and was told **the port was in use — which it had not been
before**. He changed the port and Join worked immediately.

Step 4 proves step 2: something held the listening socket while nothing served on it, and
switching off did not release it.

**What is NOT the bug**, established by reading `network_mcp/server.py` — record this so
it is not re-derived:

* `stop()` is correct. It releases unconditionally, and its docstring already anticipates
  this failure: *"a stop that released two of three listeners would leave the third bound
  with nothing behind it."*
* Every failure path inside `start()` is correct — the exception between bind and task
  creation, a task that dies during the startup wait, and the wedged-bind timeout.
* `self._sockets` is genuinely populated by `_open_listeners`, so `_release_sockets()` is
  not closing an empty tuple.

**Two candidates, both unproven at the time of writing:**

* **A1 — nothing watches the serve task for death.** `running` is
  `self._task is not None and not self._task.done()`. There is no `add_done_callback`
  anywhere in the module and nothing else observes that task. A `_guarded_serve` that ends
  *after* a successful start leaves `self._sockets` unreleased while the stored config
  still says enabled.
* **A2 — a replaced server object takes its sockets with it.** `_bring_up` builds a new
  `NetworkMCPServer`; `_apply_endpoint` keeps a server object even while switched off.
  Publishing a new object over one still holding bound sockets, without awaiting `stop()`
  on the old one, makes those sockets unreachable — no reference, no release.
  `_stop_quietly` swallows exceptions, so a failed stop is silent.

**The property to hold:** a socket this process opened is released the moment nothing is
serving on it, by *every* route out of serving — clean stop, task death, failed start, and
a server object being replaced. Several may be open at once; a leak on one of three bound
addresses is harder to see than this was.

### The decisive test — do not lose this

**His sequence: enable, disable, enable again on the same port.** Assert on whether the
port is **actually bindable**, never on what the object says about itself. The entire
defect is an object whose state disagreed with reality, so nothing it reports about itself
is evidence.

A scratch probe of the right shape is preserved at `8a4d7b9` on branch
`p24-socket-lifecycle` (pushed as `worktree-agent-ae880441703a0be49`):
`tests/integration/test_p24_probe.py`. It has a `_bindable(host, port)` helper and kills
the serve task directly. **It is unfinished and is not a passing test.**

---

## B. The enabled checkbox asserts a state it never checks

"Enabled" is a stored setting. "Listening" is a fact about now. He was shown the setting
and reasonably inferred the fact.

The endpoint block must show the running state: bound and listening on these addresses, or
enabled-but-not-serving and, where knowable, why. The page's own copy already promises
this — it says that if something is not possible "you will be told so here rather than left
guessing" — and he was left guessing.

Use the `degraded` flag and `bind_failures` list that already exist on
`NetworkEndpointInfo` rather than inventing a parallel notion of health. A partial bind —
two of three addresses listening — is neither on nor off and must read correctly. Keep the
enabled control: he must still be able to express intent. What changes is that the page
also tells him the truth about now.

---

## C. The answer appears where the question was not asked

`<form method="post" action="/network-mcp/join">` carries no anchor fragment. On a refusal
the server re-renders the whole page and the browser lands at the top; `#nm-join` starts
around template line 195 and the error renders at ~204 — below the entire endpoint block,
an 8-row address list, the identity table and the fingerprint.

**He had the diagnosis on screen from his first press and could not see it.** This is what
made A and B invisible for as long as they were, and it is a silent failure by
construction.

Applies to the join, success, cancel, removal and export paths — anything that posts and
re-renders that page.

---

## Already done, so nobody re-opens them

Both landed in `v0.1.0-alpha.14`:

* **CSRF on the settings UI** — `ui/backend/csrf.py`, raw ASGI so WebSocket scopes are
  covered too. No configuration of any kind; refusals are worded pages.
* **The show-once bearer token panel is removed**, with six stale references corrected.
  There is now no screen anywhere in this product that asks a person to copy a credential
  by hand.

## Still open, unrelated to tonight

Three CI failures, unchanged since 2026-09-05 and visible on every release page since
alpha.13: `test_b7_families_end_to_end` ×2 and
`test_shell_files_jobs.py::TestShell::test_a_cwd_inside_a_root_is_used`.
