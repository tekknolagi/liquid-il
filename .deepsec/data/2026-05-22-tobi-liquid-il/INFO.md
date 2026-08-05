# 2026-05-22-tobi-liquid-il

## What this codebase does

LiquidIL is a Ruby gem that compiles untrusted Liquid templates into Ruby source
code, evaluates that source into a `RubyVM::InstructionSequence` binary, and
persists the binary as a versioned "artifact" in a remote cache (memcache/DB).
A separate production process loads the artifact cold and renders it with
per-request assigns. The pipeline is: Liquid source → Lexer → Parser → IL →
optimization passes → RubyCompiler (IL-to-Ruby lowering) → ISeq binary →
Artifact v2 envelope → `RenderExecutor`. There is no interpreter VM in the
production path; YJIT executes the generated Ruby directly.

## Auth shape

There is no authentication or authorization layer — LiquidIL is a library, not a
service. The security boundary is **template trust vs. host trust**:

- **`Drop`** (`lib/liquid_il/drops.rb`): whitelist-based gateway for Ruby objects
  in templates. Only explicitly defined subclass methods are invokable; Object/Kernel
  methods (`send`, `instance_eval`, `class`, `system`) are blacklisted. `[]` routes
  through `invoke_drop` which checks the whitelist.
- **`LiquidDropCompat.sanitize`**: wraps `Liquid::Drop` subclasses, passes
  primitives through, returns `nil` for unknown objects (reject-by-default).
- **`Filters.register`** (`lib/liquid_il/filters.rb`): global filter registry.
  Hosts register filter modules; templates can only call registered filters.
  `pure: true` marks filters with no side effects.
- **`Tags.register`** (`lib/liquid_il/tags.rb`): custom tag registry. Hosts
  register tags with `:passthrough`, `:discard`, or `:block` modes plus
  setup/teardown callbacks that emit IL.
- **`Context`** (`lib/liquid_il/context.rb`): per-parse configuration including
  `strict_variables`, `strict_filters`, `error_mode`, `resource_limits`, and
  `file_system` (partial source provider).

## Threat model

The primary attacker is a template author with untrusted input who wants to break
out of the Liquid sandbox into arbitrary Ruby execution. Two vectors: (1) code
injection during compilation — template-derived values interpolated raw into
emitted double-quoted Ruby strings would allow `#{}` evaluation; (2) artifact
tampering — if an attacker can write the remote cache, they can substitute a
malicious ISeq binary that executes arbitrary code on load.

## Project-specific patterns to flag

- **Raw string interpolation in emitted Ruby** — The critical invariant (AGENTS.md
  §"Security invariant"): every template-derived string must be emitted through
  `.inspect` so `#{}`, quotes, and backslashes are escaped. Grep for emitted
  double-quoted strings that interpolate template values without `.inspect`.
  The codegen routes through `expression_helpers.rb#literal_ruby` and
  `ruby_compiler.rb` (e.g. `_S.lookup(#{name.inspect})`). Any bypass of this
  routing is a code-injection primitive.

- **`Marshal.load` on untrusted artifacts** — `artifact.rb` has a legacy
  pre-v1 path that calls `Marshal.load(blob)` then
  `RubyVM::InstructionSequence.load_from_binary`. v2 artifacts use JSON
  metadata to avoid arbitrary object construction. Flag any new `Marshal.load`
  on cache-sourced data; the v2 envelope deliberately avoids it.

- **`RubyVM::InstructionSequence.load_from_binary` on unauthenticated artifacts**
  — `artifact.rb#decode` and `ruby_compiler/cache_store.rb` both call
  `load_from_binary(...).eval`. ISeq binaries are executable code. If the remote
  cache is writable by an untrusted party, the host must authenticate (e.g. HMAC)
  before loading. Flag code paths that load artifacts without authentication
  checks.

- **`Drop` whitelist bypass** — `drops.rb` blacklists Object/Kernel methods to
  prevent `send`, `instance_eval`, `class`, `system` from being called via
  templates. Flag any new `Drop` subclass that overrides `invoke_drop` or
  `invokable_methods` in a way that widens the whitelist beyond subclass-defined
  methods.

- **Resource limit circumvention** — `Context` supports `output_limit` and
  `render_score_limit` to bound template output and computation. The compiler
  only emits limit-check calls when `@has_resource_limits` is true. Flag
  codepaths that skip `increment_render_score!` / `check_output_limit!` in
  generated loop/partial bodies when limits are configured.

## Known false-positives

- **`eval_ruby` in `ruby_compiler.rb`** — Compiles generated Ruby source into an
  ISeq via `RubyVM::InstructionSequence.compile(...).eval`. This is the intended
  codegen path, not `eval` of user input. Generated source is produced from
  already-validated IL; template strings are emitted as `.inspect` literals.

- **`Marshal.load` in `artifact.rb` legacy path** — Only reached for pre-v1
  cache payloads during migration. v2 artifacts use JSON metadata. The code
  comment explicitly warns callers should only load trusted artifacts.

- **`integration/storefront_mock/`** — Mock adapter and test harness for the
  storefront integration. Contains `mock_theme.rb`, `mock_key_value_store.rb`,
  etc. These are development fixtures, not production code paths.

- **`spec/repros/` and `test/`** — Test specs and unit tests. YAML repro specs
  contain intentionally malformed or edge-case Liquid templates. Not production
  surfaces.
