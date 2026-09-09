# Decision record — the network MCP endpoint (subtask B4)

Two decisions were explicitly delegated to this subtask. Both are recorded here with their
reasoning, because the reasoning is the part that has to survive.

---

## 1. `mcp` package vs. extending the inline JSON-RPC — **the `mcp` package, server side only**

### What was chosen

`mcp.server.lowlevel.Server(...).streamable_http_app()` provides the `/mcp` endpoint. Our own
ASGI middleware (`hardening.py`) sits *in front of* it and owns path routing, bearer-token
authentication, byte bounds, structural validation and the connection cap. The SDK owns the
wire protocol; we own the security boundary.

`mcp` is now a declared dependency in `pyproject.toml`. It was already resolved into the venv
as a direct requirement of `claude-agent-sdk`, so this adds no wheel — it makes an existing,
already-shipped transitive dependency honest.

**The original rejection stands where it was made.** `MCPStdioClient`
(`mcp_host/mcp_client.py`) is *not* replaced. `mcp`'s `stdio_client` wants to spawn the plugin
subprocess itself via `anyio.open_process()` with `get_default_environment()`, which bypasses
both our Job Object wrapping and our environment whitelist. That objection is about process
spawning; the streamable-HTTP *server* transport spawns nothing and touches no subprocess
isolation, so the objection does not reach it. The `pyproject.toml` note has been amended, not
deleted.

### Why

1. **Wire-protocol interoperability is the dominant risk in this subtask, and it is untestable
   by hand.** The core connects with `mcp` 2.x's `streamable_http_client`
   (`plugins/mcp_client.py:830`, contract §3). Streamable HTTP is not "JSON-RPC over POST": it
   is `Mcp-Session-Id` issuance and echo, `MCP-Protocol-Version` negotiation, `Accept`-header
   discrimination between `application/json` and `text/event-stream`, SSE framing with
   resumable event ids and `Last-Event-ID` replay, `202 Accepted` for notifications, `DELETE`
   for session teardown, and initialization ordering. A hand-rolled server that gets any of
   that subtly wrong presents as a **terminal load failure** on the core (contract §2), and
   A6 — the hands-on acceptance pass that would have caught it — is externally blocked. Running
   the same SDK on both ends deletes that entire class of defect rather than testing for it.

2. **The reason it was dropped no longer applies.** The `pyproject.toml` note cited a clash
   with PersonaCore's pinned `mcp` 2.x. The Agent now has its own venv at `.venv/`, so there is
   no shared site-packages to clobber, and the benefit is no longer "zero" — it is the whole
   transport.

3. **It costs us none of the hardening.** Everything the inherited B0 crash classes demand
   happens in our middleware, *outside* the SDK app: an unauthenticated request never has a
   single body byte read, never reaches a JSON parser, and never allocates a session. The SDK
   additionally offers bounds a hand-rolled server would have had to reinvent —
   `max_request_body_size`, `max_sessions`, `session_idle_timeout`, and
   `TransportSecuritySettings` Host/Origin validation against DNS rebinding.

4. **Stateful mode gives B2 the session identifier it needs.** B2 must plumb a
   session/connection identifier from the transport into the permissions evaluator so B3's
   "remember for this session" is implementable. `Mcp-Session-Id` is exactly that identifier
   and the SDK issues and tracks it for us. `stateless_http=False` is therefore deliberate.

### What was *not* used, and why

The SDK's own auth (`auth=`, `token_verifier=`, `RequireAuthMiddleware`) is OAuth 2.1 resource-
server machinery: it advertises protected-resource metadata and returns `WWW-Authenticate`
challenges pointing at an authorization server. Contract §3 specifies a static 32-byte bearer
token and a `401` **with no body detail**. Using the OAuth path would leak endpoint metadata to
unauthenticated peers and answer a different question than the one the contract asks. Our
middleware is ~40 lines and says exactly what the contract says.

### Accepted costs, stated

- `mcp` becomes a direct dependency of a PyInstaller-frozen binary, and we inherit the SDK's
  protocol-version cadence. Accepted: the alternative is inheriting the *same* cadence in a
  reimplementation that nobody conformance-tests.
- The pin is narrow (§3), so an SDK upgrade is a deliberate decision with a verification step
  rather than something a fresh `pip install` can do behind our back.

---

## 3. The `mcp` version — **pinned to `>=2.1.1,<2.2`, the version the core runs**

### What went wrong first, because the fix only makes sense against it

The first cut of this module declared `mcp>=2.1,<3.0` and passed `max_sessions=` and
`session_idle_timeout=` to `Server.streamable_http_app()`. Both exist on 2.2's signature.
**Neither exists on 2.1.1's.** A fresh worktree resolved the floor to 2.2.0, so the whole suite
passed locally; applied to a tree with 2.1.1 installed it produced `4 failed, 57 errors`, every
one of them `TypeError: Server.streamable_http_app() got an unexpected keyword argument
'max_sessions'`.

Two things were wrong, and only one of them was the keyword argument:

1. **The declared dependency did not describe the code.** A constraint that admits a version the
   code cannot run on is not a constraint.
2. **It quietly repealed §1's central argument.** The SDK was adopted *because* running the same
   SDK on both ends deletes a class of wire-protocol bugs that A6 — externally blocked — cannot
   catch by hand. A 2.2.0 server against a 2.1.1 client is not the same SDK on both ends. The
   version floor reintroduced, silently, the exact risk the dependency was taken on to remove.

### The decision

**Target 2.1.1.** Contract §12 records the core's version twice, introspected, and §3 quotes
2.1.1's client signature directly. `pyproject.toml` now says `mcp>=2.1.1,<2.2`, which excludes
2.2 rather than merely preferring 2.1 — so "the same SDK on both ends" is enforced by the
constraint instead of being hoped for. `claude-agent-sdk` asks only for `mcp>=1.23.0,<3.0.0`, so
nothing else in the tree is squeezed by this.

Only keyword arguments present in **every** admitted version are passed:
`streamable_http_path`, `stateless_http`, `json_response`, `max_request_body_size`,
`transport_security`, `host`.

### What replaced the two dropped arguments

- **`session_idle_timeout`** is still applied, just not through the app factory.
  `StreamableHTTPSessionManager` takes it as a documented constructor parameter in both 2.1.1 and
  2.2 and stores it on a public attribute of the same name, read live as each session is created;
  2.1.1's `streamable_http_app` simply does not forward it. Setting
  `server.session_manager.session_idle_timeout` reaches it without reimplementing the factory's
  routing and lifespan wiring. This matters: without it the SDK drops a session only on an
  explicit `DELETE`.
- **`max_sessions`** moved into `hardening.py`, which already owns every other limit — a net
  simplification, since the bound now lives in the layer that is unit-testable without a socket
  and does not move between SDK minor versions. The accounting deliberately mirrors the SDK's own
  lifecycle so the two cannot drift: a `POST` with no `Mcp-Session-Id` is the only thing the cap
  refuses (before the SDK allocates a transport), any request carrying a known id refreshes it,
  and idle expiry uses the same timeout handed to the session manager.

  **Expiry is not optional there.** Counting only creations and teardowns would make a peer that
  reconnects without sending `DELETE` — which is what happens every time the core restarts — leak
  a slot per restart, and after `max_sessions` restarts the endpoint would refuse the core
  outright. That converts the SDK's memory leak into an outage, which is strictly worse than the
  thing the cap exists for.

### How this is prevented from recurring

`_require_mcp_api()` runs at the top of `NetworkMCPServer.start()`, before a certificate is
loaded or a port is touched, and raises a `RuntimeError` naming the installed version, the exact
missing API, and the reinstall command. A `TypeError` out of the SDK at first bind on an
operator's machine is the worst possible discovery point: the Agent is already running, the UI has
already shown a URL, and the message names a keyword argument rather than a dependency.

`tests/unit/network_mcp/test_mcp_compat.py` then covers both obligations. It parses
`pyproject.toml` and asserts the declared range admits 2.1.1 and that the *installed* version
satisfies the declared range — so the suite cannot silently be testing something other than what
ships. And it intercepts `Server.streamable_http_app`, records the keyword arguments the code
really passes, and checks each against the installed signature: that test fails on the next
2.2-only keyword anybody adds, whether or not they remember to update the declared list.

---

## 2. The pre-authentication input bound — **64 KiB, and no body read at all before auth**

### The bound

| stage | bound | enforced by |
|---|---|---|
| request line + headers | 16 KiB (`MAX_HEADER_BYTES`) | uvicorn's h11 parser, configured explicitly, before ASGI |
| **pre-auth body** | **0 bytes** | `Hardening` answers `401` from the scope, never calling `receive()` |
| post-auth body | 1 MiB (`max_request_bytes`, configurable) | `Content-Length` checked on the header; streamed bodies counted while draining and aborted at the bound |
| post-auth body read time | 10 s | `asyncio.timeout` around the drain loop |
| concurrent requests | 16 (`max_connections`) | in-flight counter, `503` over the cap |
| JSON nesting depth | 64 | iterative pre-scan, before `json.loads` |

### Why these numbers

B0 was required to justify anything above asyncio's 64 KiB default, after a 64 MiB limit was
rejected for trading a crash for memory exhaustion — an unauthenticated client could pin 64 MB
per connection. That objection is the design input here, and HTTP lets us do better than pick a
smaller number.

**The strongest available answer is not a smaller buffer, it is no buffer.** Authentication over
HTTP is a header check. `Hardening` answers `401` from the ASGI `scope` alone: it never calls
`receive()`, so an unauthenticated peer's body is never read, never decoded, never parsed, and
never allocated. So the chosen pre-authentication body bound is **zero bytes** — strictly below
B0's 64 KiB, and below any number that could have been argued for.

That leaves exactly one thing an unauthenticated peer can make this process hold: the header
block. That bound is not left to a library default — `MAX_HEADER_BYTES` (16 KiB) is passed to
uvicorn as `h11_max_incomplete_event_size`, with `http="h11"` pinned so the parser enforcing it
is the one we configured. Combined with the 16-request concurrency cap, the total unauthenticated
memory ceiling is **256 KiB across the whole server** — a stated number, not an emergent one.

Note the ordering consequence, which is deliberate: an unauthenticated request with a 1 GiB
`Content-Length` gets `401`, not `413`. Answering `413` would mean deciding the size question
before the identity question, and would tell an unauthenticated peer what our bounds are. The
size checks run only after the token is known good.

The **post-auth** bound is 1 MiB rather than the SDK's 4 MiB default. The largest legitimate
request is a `files_write` or `adb_push` argument object; §5.3 caps *results* at 60,000
characters and arguments are smaller still, so 1 MiB is ~17× the largest legitimate payload —
generous without being a memory lever. It is configurable because `files_write` is the one tool
whose ceiling an operator might genuinely need to raise.

### Rejecting early rather than buffering to reply politely

Every rejection in `Hardening` is decided from the `scope` or from a header, before any body byte
is consumed:

- plaintext transport → `403`, token never read
- missing/bad/duplicated token → `401`, no body read, no detail
- wrong path (authenticated) → `404`, no body read
- wrong method (authenticated) → `405`, no body read
- over the concurrency cap → `503`, no body read
- `Content-Length` over the bound → `413`, no body read

**That order is itself a security property**, and three of the five positions are load-bearing:

- **Transport first.** Reading a bearer token off a plaintext connection is already the harm — by
  the time we could compare it, it has crossed the LAN in the clear. `NetworkMCPServer` always
  configures TLS, so nothing reaches this middleware over plain HTTP today; the check is here
  anyway because this is a reusable ASGI middleware and the guarantee should be local to the file
  that promises it, not to a uvicorn config three files away.
- **Identity before path and method.** Answering `404` for an unknown path and `405` for an
  unknown method ahead of the token check would let an anonymous peer map this surface by telling
  the three answers apart, and fill the log without ever constructing an `Authorization` header.
  An unauthenticated peer now gets `401` for everything.
- **Identity before the cap.** `_in_flight` counts only authenticated requests, so answering an
  unauthenticated peer `503` would both tell it how busy this machine is and let a flood of
  anonymous requests deny the core its slot.

Only a request that has cleared all five has its body drained, and the drain itself is bounded
in both bytes and seconds: an oversized *streamed* body (no `Content-Length`) aborts the drain
mid-stream rather than buffering the remainder in order to reply politely, and a slow-loris
partial send is cut off by the 10 s `asyncio.timeout`.

Every rejection also sets `Connection: close`, so a peer we just refused does not keep a slot on
a keep-alive connection against the concurrency cap.

Rejection logging is itself rate-limited (first occurrence at WARNING, then every 50th, carrying
the running total). Unbounded logging on an unauthenticated LAN endpoint is a disk-exhaustion
lever, and the pattern is the same class of mistake as an unbounded read buffer.
---

## 4. Binding several addresses — **our own sockets, one uvicorn server** (subtask P13)

### The problem

The endpoint binds a set of operator-chosen addresses, because a machine that bridges two
networks has to answer on both. `uvicorn` binds **one** host per `uvicorn.Server`.

### What was chosen

`listeners.open_listeners()` creates one bound `socket` per chosen address, and the whole list
is handed to a single `uvicorn.Server.serve(sockets=[...])`, over a single ASGI app.

### Why, and what the alternative would have cost

The alternative is N `uvicorn.Server` instances. Each has its own lifespan, its own
`should_exit` flag and its own graceful-shutdown clock — and the MCP SDK's
`StreamableHTTPSessionManager` is started *by the lifespan* and is not re-entrant. Sharing one
app across N lifespans starts N session managers over one server object: two views of "live
session", two idle reapers, and a shutdown that has to be choreographed across N servers that
can each fail independently. Building one app per address instead gives N bearer gates and N
enrolment windows, so a Join opened on one address would be invisible on the others.

`Server.serve(sockets=...)` calls `loop.create_server(sock=...)` once per socket and
`Server.shutdown` closes every socket it was given, so all of them start and stop as one.
`NetworkMCPServer.stop` closes them again itself, because "stopping released every socket" must
not depend on uvicorn having reached its shutdown path.

### What binding here (rather than in uvicorn) buys

- **A partial bind is reportable.** Each address fails on its own `bind()` with its own errno,
  so `info().bind_failures` can say *which* address and *why*. uvicorn's own bind path answers
  with `sys.exit(3)` and could never name an address — it only ever had one.
- **`SO_REUSEADDR` is not set on Windows.** There it lets a second process bind an
  address:port another process is already listening on, which would turn the one failure this
  needs to report into a silent success. It is set on POSIX, where it means TIME_WAIT reuse.
- **`IPV6_V6ONLY` is set.** An IPv6 socket that also accepts IPv4 is a wildcard the operator
  did not choose.
- **`port = 0` picks one port for the whole set.** The first socket to bind fixes it and the
  rest are bound to that port explicitly; one endpoint answering on three different ports is
  not one endpoint.

### The SAN rule lives here too

`open_listeners` refuses to bind an address the endpoint certificate does not cover. That is
the invariant that does not depend on the UI: whatever reaches the config — a crafted POST, a
hand-edited file, a stale page — nothing puts a listener on an address it cannot present a
matching certificate for. The refusal is reported as an ordinary bind failure, so the operator
is told which address and offered the regeneration, rather than the endpoint refusing to serve
at all.
