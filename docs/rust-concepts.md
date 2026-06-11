# Rust concepts in pincer — a guided tour

Every Rust concept this codebase uses, explained from the ground up and tied to
the exact place it appears. Written for someone newer to Rust. Read it with the
source open; each section points at a real file.

Order matters — later sections build on earlier ones. If you read top to bottom
you'll understand the whole codebase.

---

## 1. Ownership — the one idea Rust is built on

Every value in Rust has exactly **one owner** (one variable responsible for it).
When the owner goes out of scope, the value is freed. No garbage collector, no
manual `free()` — the compiler inserts the cleanup, and guarantees it happens
exactly once.

```rust
let frame = vec![0u8, 1, 2];   // `frame` owns this heap-allocated Vec
// ... use frame ...
// at the end of the block, `frame` is dropped and its memory freed — automatically
```

If you **move** a value, ownership transfers and the old variable can't be used:

```rust
let a = vec![1, 2, 3];
let b = a;          // ownership MOVES to b
// println!("{a:?}"); // ERROR: a no longer owns anything
```

This is why our functions are careful about taking values by reference (below)
vs by value. The fixture builder *consumes* `self` on each step
(`pub fn ipv4(self, ...)`) — it takes ownership so the previous stage can't be
reused, which is the whole point of the typestate pattern (§19).

---

## 2. Borrowing & references — using without owning

You usually don't want to give away ownership just to *look* at something. A
**reference** (`&T`) borrows a value without taking it:

```rust
fn total(bytes: &[u8]) -> usize { bytes.len() }  // borrows, doesn't own
let frame = vec![1, 2, 3];
let n = total(&frame);   // lend it
// `frame` is still usable here — we only borrowed it
```

Two rules the compiler enforces (the "borrow checker"):
1. You can have **many** shared references `&T` (read-only), **or**
2. exactly **one** mutable reference `&mut T` (read-write), but never both at once.

This prevents data races and use-after-free *at compile time*. It's the source
of most "fighting the borrow checker" early on, but it's also what lets us write
a zero-copy parser with zero memory bugs.

In `pincer`, `&[u8]` (a borrowed slice of bytes) is everywhere — every decoder
*borrows* the packet bytes rather than copying them. `&mut self` appears on
methods that mutate, like `Cursor::take(&mut self, ...)` (it advances the
cursor's position) and `FlowTable::observe(&mut self, ...)` (it updates the
table).

---

## 3. Lifetimes — "how long is this borrow valid?"

This is the concept people find hardest, so slowly. A reference must never
outlive the thing it points to (or you'd have a dangling pointer). Usually Rust
figures this out silently. But when a *struct* holds a reference, you must name
how long that borrow lasts, with a **lifetime parameter** written `'a`:

```rust
pub struct Cursor<'a> {     // "a Cursor that borrows some bytes for lifetime 'a"
    data: &'a [u8],         // the borrowed bytes
    pos: usize,
}
```

Read `'a` as "some span of time during which the borrowed data is guaranteed to
exist." The `Cursor` cannot outlive the `&[u8]` it was built from — the compiler
guarantees it.

This ripples through the decode layer. A `PacketView<'a>` borrows the packet
buffer:

```rust
pub struct PacketView<'a> {
    pub net: NetView<'a>,           // sub-views borrow the same buffer
    pub transport: Option<TransportView<'a>>,
    // ...
}
```

The payoff is huge and worth calling out: **because the
lifetime ties a `PacketView` to the buffer it came from, you physically cannot
keep a packet view after the buffer is reused for the next packet.** The borrow
checker enforces the streaming discipline. If you tried to collect packet views
into a `Vec` to use later, it wouldn't compile. Memory-safety bugs that would be
runtime crashes in C are compile errors here.

The `'_` you see (e.g. `Record<'_>`) is the "anonymous lifetime" — "there's a
lifetime here, infer it." It's shorthand when you don't need to name it.

---

## 4. Slices — `&[u8]`, the zero-copy workhorse

A **slice** `&[T]` is a *view* into a contiguous run of values: a pointer + a
length. It owns nothing. `&[u8]` (a slice of bytes) is the single most common
type in this codebase because a packet *is* a run of bytes, and we want to look
at windows of it without copying.

```rust
let frame: Vec<u8> = vec![/* ... */];
let ethernet_header: &[u8] = &frame[0..14];  // a view of the first 14 bytes — no copy
```

When `Cursor::take(5)` returns `&'a [u8]`, it's handing back a 5-byte *window*
into the original buffer — no allocation, just a pointer and a length. This is
literally what "zero-copy" means: a million packets, zero per-packet
allocations.

(Note: we never write `&frame[0..14]` directly in parsing code — that could
panic if the frame is too short. We go through `Cursor` instead, §6 and §20.)

---

## 5. Structs and enums — modelling data

**Structs** group related fields:

```rust
pub struct TcpView<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: TcpFlags,
    pub payload: &'a [u8],
}
```

**Enums** model "one of several possibilities" — and Rust enums are far more
powerful than in most languages because each variant can carry different data:

```rust
pub enum NetView<'a> {
    Arp(ArpView),                 // an ARP packet, carrying an ArpView
    Ipv4(Ipv4View<'a>),           // an IPv4 packet
    Ipv6(Ipv6View<'a>),
    Unknown { ethertype: u16 },   // some other type, carrying its number
    Malformed { layer: &'static str, err: DecodeError },  // couldn't decode
}
```

A `NetView` is *exactly one* of these at a time, and the compiler forces you to
handle every case (§7). This is how we model "the network layer is either ARP,
or IPv4, or … or couldn't be decoded" precisely, with no nulls and no "is this
field valid?" guesswork. The whole decode layer is enums like this.

---

## 6. `Option` and `Result` — no nulls, no exceptions

Rust has **no null** and **no exceptions**. Instead, two enums from the standard
library express "maybe" and "fallible":

```rust
enum Option<T> { Some(T), None }              // a value, or nothing
enum Result<T, E> { Ok(T), Err(E) }           // success with T, or failure with E
```

We use `Option` for "this might not be present": a flow's `server_name()` returns
`Option<&str>` — maybe we saw a hostname, maybe not. We use `Result` for "this
operation can fail with a reason": `Cursor::take` returns
`Result<&[u8], DecodeError>` — you get the bytes, or a decode error explaining
what went wrong.

Crucially, the type *forces* the caller to deal with the absence/failure — you
can't accidentally use a missing value, because it's wrapped. This is half of why
Rust programs don't segfault.

Our three-tier error model (`Result<_, PcapError>` vs `Result<_, DecodeError>`
vs `Option`) is a deliberate use of this: the *return type* of a function tells
you how a failure should be treated. See [DESIGN.md](../DESIGN.md) §4.

---

## 7. Pattern matching — `match`, `if let`, `let else`

You take `Option`/`Result`/enums apart with **pattern matching**. `match` is
exhaustive — the compiler errors if you forget a case, which is why adding a new
enum variant safely points you at every place that needs updating:

```rust
match &pkt.net {
    NetView::Ipv4(ip) => /* use ip */,
    NetView::Ipv6(ip) => /* use ip */,
    NetView::Arp(arp) => /* use arp */,
    NetView::Unknown { ethertype } => /* use the number */,
    NetView::Malformed { .. } => /* .. ignores the fields */,
}
```

When you only care about *one* case, `if let` is shorter:

```rust
if let Some(event) = app {        // only do this when `app` is Some
    flow.apps.push(event.clone());
}
```

`let ... else` (used heavily in our parsers) binds a value or bails out — it
keeps the happy path un-indented:

```rust
let Some((src_ip, dst_ip)) = pkt.ip_pair() else {
    return;     // no IP layer? nothing to do — leave early
};
// from here on, src_ip and dst_ip are available, no nesting
```

And Rust 2024 **if-let chains** let you combine conditions:

```rust
if let Some(event) = app
    && flow.apps.len() < MAX_APP_EVENTS   // both must hold
{
    flow.apps.push(event.clone());
}
```

These appear constantly in `decode/` and `analysis/` — they're how you handle
the "maybe present, maybe malformed" reality of packets without a pyramid of
nested `if`s.

---

## 8. The `?` operator — propagate failure cleanly

Writing `match` on every fallible call would bury the logic. The `?` operator
says "if this is `Err`/`None`, return it from the whole function; otherwise give
me the inner value":

```rust
pub fn parse<'a>(cur: &mut Cursor<'a>) -> Result<Ipv4View<'a>, DecodeError> {
    let ver_ihl = cur.u8()?;       // if u8() fails, return that DecodeError now
    let total_len = cur.u16_be()?; // same
    // ... only reached if every read succeeded
}
```

Every decoder is written this way: a straight-line sequence of `?`-terminated
reads that reads like the packet's byte layout, with all the error-handling
implicit. This is *the* idiomatic Rust error-handling style. The `?` also works
on `Option` (returns `None` early), which our app sniffers use.

---

## 9. Error types with `thiserror`

Defining a good error enum by hand means writing `Display` and `Error` impls.
The `thiserror` crate generates them from attributes ([error.rs](../src/error.rs)):

```rust
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("truncated: needed {needed} bytes, had {have}")]   // the Display message
    Truncated { needed: usize, have: usize },
    #[error("malformed {layer}: {reason}")]
    Malformed { layer: &'static str, reason: &'static str },
}
```

`#[derive(thiserror::Error)]` writes the boilerplate; `#[error("…")]` defines the
human message, interpolating the fields. `#[from]` (used in `Error::Io`) auto-
generates a conversion so `?` can turn a `std::io::Error` into our error. This is
the standard way to do library errors in Rust.

---

## 10. Traits — shared behaviour

A **trait** is a set of methods a type can implement — like an interface. The
defining one in `pincer` is `Observe` ([analysis/mod.rs](../src/analysis/mod.rs)):

```rust
pub trait Observe {
    fn observe(&mut self, pkt: &PacketView<'_>, app: Option<&AppEvent>);
}
```

Any analysis that implements `observe` can be driven by the single-pass loop.
`FlowTable`, `AssetInventory`, and `Stats` each `impl Observe for …`. The loop
doesn't care which is which — it just calls `.observe(...)`. That's polymorphism.

We also implement **standard-library traits** to plug into the ecosystem:
- `impl Display for MacAddr` — defines how it prints (`aa:bb:cc:...`), so
  `format!("{mac}")` and `.to_string()` work.
- `impl From<u8> for DhcpMsgType` — defines a conversion, so `DhcpMsgType::from(3)`
  and `.into()` work.
- `#[derive(Serialize)]` — the `serde` crate's trait that enables `--json`.

### Generics vs trait objects

There are two ways to be generic over "anything that implements a trait":

- **Generics / `impl Trait`** (static, zero-cost): `CaptureReader<R: Read>` works
  with any reader type, and the compiler generates a specialized version for each
  — no runtime cost. We use this for the reader so it works on a file *or* an
  in-memory `&[u8]` (tests use the latter).
- **Trait objects** (`dyn Trait`, dynamic dispatch): a runtime pointer to "some
  type implementing the trait." We don't need these here; generics suffice and
  are faster.

---

## 11. Generics and trait bounds

A **generic** function/type works for many types, constrained by **bounds**
(`R: Read` means "any `R` that implements the `Read` trait"):

```rust
pub struct CaptureReader<R> { reader: R, /* ... */ }

impl<R: Read> CaptureReader<R> {            // methods available when R: Read
    pub fn new(mut reader: R) -> Result<Self, PcapError> { /* ... */ }
}
```

Because `CaptureReader` is generic over `R: Read`, the *same code* reads from a
`File`, a `BufReader<File>`, or a `&[u8]` slice (which also implements `Read`).
That's why every test can build a capture in memory and read it back without
touching the disk — a big reason the tests are fast and hermetic.

---

## 12. The newtype pattern

A **newtype** is a single-field struct wrapping another type, to give it identity
and behaviour:

```rust
pub struct MacAddr(pub [u8; 6]);   // a MAC is more than "six bytes"
```

Why bother? Three wins:
1. **Type safety** — a `MacAddr` can't be passed where an `Ipv4Addr` or a random
   `[u8; 6]` is expected; the compiler catches the mix-up.
2. **Behaviour** — we hang methods on it: `is_multicast()`, `is_broadcast()`, and
   a `Display` impl that formats it as `aa:bb:cc:dd:ee:ff`.
3. **Invariants** — for `FlowKey` (§13), the newtype's constructor enforces a
   rule no caller can bypass.

`Timestamp` and `IpProto` are newtype-style wrappers for the same reasons.

---

## 13. Smart constructors and invariants

A **smart constructor** is the only public way to build a type, and it enforces a
rule. `FlowKey::new` is the example:

```rust
impl FlowKey {
    pub fn new(x: Endpoint, y: Endpoint, proto: IpProto) -> Self {
        let (a, b) = if x <= y { (x, y) } else { (y, x) };  // always sort
        Self { a, b, proto }
    }
}
```

The fields `a` and `b` are **private**, so the *only* way to get a `FlowKey` is
through `new`, which always stores the smaller endpoint first. Result: a packet
from A→B and a packet from B→A produce the **identical** key, so both directions
of a conversation land in the same flow — guaranteed by construction, not by
hoping every caller remembers to sort. The invariant has exactly one home.

---

## 14. Closures

A **closure** is an anonymous function that can capture variables from its
surroundings: `|args| body`. We use them as lightweight callbacks and in iterator
chains:

```rust
// a closure that captures `frames` and pushes to it
let mut push = |millis: u64, frame: Vec<u8>| frames.push((at(millis), frame));

// closures passed to iterator adapters
flows.sort_by_key(|flow| std::cmp::Reverse(flow.total_bytes()));
let ips: Vec<String> = asset.ips.iter().map(ToString::to_string).collect();
```

`ok_or_else(|| DecodeError::truncated(...))` (in `Cursor`) takes a closure that's
only called on the error path — so we don't build the error value unless we
actually need it.

---

## 15. Iterators and adapters

An **iterator** produces a sequence of values lazily. **Adapters** transform one
iterator into another without running anything until you *consume* it (with
`collect`, `find`, `for`, etc.). This style replaces most manual loops:

```rust
// "find the first answer that is an A or AAAA record, attribute it to an asset"
flow.apps.iter().find_map(|app| match app {
    AppEvent::Tls(hello) => hello.sni.as_deref(),
    AppEvent::Http(req)  => req.host.as_deref(),
    _ => None,
})
```

- `.iter()` — borrow each element in turn
- `.map(f)` — transform each element
- `.filter(p)` — keep elements matching a predicate
- `.find(p)` / `.find_map(f)` — first match
- `.collect()` — gather results into a `Vec`/`String`/map

`flows.rs`, `assets.rs`, and `output/` lean on these heavily. They're lazy
(nothing runs until consumed), composable, and often optimize as well as a
hand-written loop.

---

## 16. `impl Trait` — anonymous return types

When a function returns "some iterator" whose exact type is an unspeakable
adapter chain, you write `impl Trait`:

```rust
pub fn iter(&self) -> impl Iterator<Item = &Flow> {
    self.flows.values()   // returns "some iterator of &Flow"; caller doesn't need the exact type
}
```

The caller gets something they can iterate; the concrete type stays hidden. Used
in `FlowTable::iter`, `VlanStack::iter`, etc. (`impl Trait` in *argument*
position, like `reader: impl Read`, is just shorthand for a generic bound.)

---

## 17. Modules and visibility

Code is organized into **modules** (`mod`), forming a tree. Items are private by
default; `pub` exposes them. `pub(crate)` exposes within this crate only:

```rust
pub mod bytes;            // a public module (in lib.rs)
pub(crate) const MAX_RECORD_LEN: usize = 64 * 1024 * 1024;  // crate-internal
fn arp_body(...) -> Vec<u8> { ... }   // private helper, file-local
```

This is real encapsulation: `FlowKey`'s fields are private so the invariant
holds; `Cursor` is `pub` so decoders can use it, but the modules that use it
can't bypass it because indexing is lint-forbidden. Visibility is a design tool,
not bookkeeping. `lib.rs` declares the module tree and re-exports the public API
(`pub use error::{...}`).

---

## 18. Derive macros and common traits

`#[derive(...)]` auto-generates trait implementations. The ones you'll see:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddr(pub [u8; 6]);
```

- **`Debug`** — `{:?}` formatting, for logs and test output. (We even `warn` on
  missing `Debug` impls so every type is inspectable.)
- **`Clone`** — explicit deep copy via `.clone()`.
- **`Copy`** — the type is cheap enough to copy implicitly on assignment (small,
  no heap). `MacAddr` is `Copy`; `String`-holding types are not.
- **`PartialEq`/`Eq`** — `==` comparison.
- **`PartialOrd`/`Ord`** — ordering (`<`, `.sort()`, use as a `BTreeMap` key).
  Note `FlowKey` derives these, which is how sorting endpoints works.
- **`Hash`** — usable as a `HashMap` key.
- **`Default`** — a zero/empty value via `Default::default()`.

Deriving these is idiomatic; hand-writing them (as we do for `Display`, where we
want custom formatting) is the exception.

---

## 19. The typestate pattern — illegal states won't compile

The fixture builder ([fixtures/mod.rs](../src/fixtures/mod.rs)) encodes the *valid
build sequence in the type system*. Each layer method consumes `self` and returns
a **different** type:

```rust
Packet::ethernet(src, dst)   // -> EthStage
    .ipv4(s, d)              // -> Ipv4Stage   (EthStage::ipv4 consumes the EthStage)
    .tcp(sp, dp)             // -> TcpStage
    .syn()                   // -> TcpStage    (a tweak)
    .build()                 // -> Vec<u8>     (the finished frame)
```

`EthStage` has no `.tcp()` method — only `Ipv4Stage`/`Ipv6Stage` do. So
`Packet::ethernet(...).tcp(...)` is a **compile error**: you can't put TCP
directly on Ethernet without an IP layer. The *type* you hold encodes *what state
the build is in* (hence "typestate"), and only legal transitions exist. Invalid
packets are unrepresentable, with zero runtime checks. This is one of Rust's
most elegant patterns and a great thing to be able to explain.

---

## 20. Integer types, checked arithmetic, and casts

Rust has explicit fixed-width integers: `u8` (0–255), `u16`, `u32`, `u64`,
`usize` (pointer-sized). Packet fields have exact widths, so we name them exactly
(`src_port: u16`, `ttl: u8`).

The subtle danger: arithmetic on attacker-controlled lengths can **overflow**.
`a + b` where both come from a packet could wrap (or panic in debug). In our
parsers, `clippy::arithmetic_side_effects` is **denied**, forcing explicit safe
arithmetic:

```rust
let end = self.pos.checked_add(n)            // returns None on overflow instead of wrapping
    .ok_or_else(|| DecodeError::truncated(n, self.remaining()))?;
let net = u32::from(v4) & 0xFFFF_FF00;       // checked_*, saturating_*, & masks
```

- `checked_add` → `Option` (None on overflow)
- `saturating_add` → clamps at the max instead of wrapping
- `wrapping_add` → explicit wrap (when you actually want it)

**Casts** use `as` (e.g. `x as u32`) but that can silently truncate, so where it
matters we use `u32::try_from(x)` which returns a `Result`. The lint
`cast_possible_truncation` nudges us toward the safe form. This discipline is why
no malformed length field can crash or corrupt the analysis.

---

## 21. `String` vs `&str`, owned vs borrowed

Two string types, mirroring `Vec<T>` vs `&[T]`:
- **`&str`** — a *borrowed* view of UTF-8 text (like `&[u8]`). No ownership.
- **`String`** — an *owned*, growable, heap-allocated string.

The choice encodes our zero-copy boundary. While decoding we pass around
borrowed `&str`/`&[u8]`. But an `AppEvent` (a fact that outlives the packet)
holds **owned** `String`s — because an asset's hostname must survive long after
its packet's buffer is reused. The general rule across the codebase: *borrow
while decoding, own when a value graduates into long-lived analysis state.* The
type (`&str` vs `String`) makes that boundary visible.

---

## 22. `BTreeMap` / `BTreeSet` — determinism by default

Rust has two main map/set families:
- **`HashMap`/`HashSet`** — fast, but iteration order is unspecified (and
  randomized per run).
- **`BTreeMap`/`BTreeSet`** — keep keys *sorted*, so iteration is deterministic.

We use the `BTree` variants throughout `analysis/` and the asset records. Why?
Because reports must be **stable**: the same capture must always produce
byte-identical output, so tests can snapshot it and humans can diff two runs.
Sorted keys give that for free (it's also why `FlowKey` derives `Ord`). We'd only
reach for `HashMap` if profiling showed the ordering cost mattered in a hot loop
— and then we'd sort only at render time.

---

## 23. The lending iterator (the reader), in depth

This ties §2, §3, and §6 together — it's the cleverest bit of the design, so
here it is slowly. We want to loop over packets, but a normal `Iterator`:

```rust
trait Iterator { type Item; fn next(&mut self) -> Option<Self::Item>; }
```

returns an `Item` the caller can **keep**. If `Item` borrowed our one reusable
buffer, the caller could hold two packets at once that both point at a buffer
we've already overwritten — unsound. The standard `Iterator` trait can't express
"each item borrows me and must be dropped before the next call" (that needs
unstable generic-associated-types). So instead the reader offers an inherent
method:

```rust
pub fn next_record(&mut self) -> Result<Option<Record<'_>>, PcapError>;
//                  ^^^^^^^^^                       ^^^^
//                  borrows the reader (&mut self)  Record borrows it back (the '_)
```

The returned `Record<'_>` borrows `self`. While you hold it, you hold a `&mut`
borrow of the reader, so you **cannot** call `next_record` again until you're
done with the current record (the borrow checker forbids it). That is *exactly*
the streaming contract: one packet at a time, one buffer, constant memory — and
the compiler enforces it rather than us hoping. The loop reads naturally:

```rust
while let Some(record) = reader.next_record()? {
    // use record; it's dropped at the end of the loop body, freeing the borrow
}
```

This is "the lending iterator pattern," and being able to explain *why it isn't
just `impl Iterator`* is a strong senior signal.

---

## 24. Attributes and lints — making the compiler enforce the rules

Attributes (`#[...]` on an item, `#![...]` on a whole module/crate) configure the
compiler. The ones that shape `pincer`:

- `#![forbid(unsafe_code)]` (in `lib.rs`) — the `unsafe` keyword is a hard error
  anywhere in the crate. Memory safety is the compiler's job, not ours.
- `[lints]` in `Cargo.toml` — `deny` turns these into errors:
  `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`,
  `arithmetic_side_effects`. Each forbids a way to crash on bad input (§20, §1
  of DESIGN).
- `#[must_use]` — warns if you call a function and ignore its result (good for
  pure functions like `Cursor::remaining`).
- `#[allow(...)]` — locally opt out. Test modules carry
  `#![allow(clippy::unwrap_used, clippy::panic)]` because a *test* should panic on
  a failed assertion — the strictness is for the library, where untrusted input
  lands.

The point: these aren't nags. Each one converts a class of runtime bug into a
compile error, so "this program cannot panic on malicious input" becomes
something the compiler helps *prove* — which we then confirm by fuzzing in
`tests/never_panic.rs`. For a packet parser, that's not extra; that's the job.

---

## Where to go next

- Re-read [DESIGN.md](../DESIGN.md) — now the patterns map onto concepts you know.
- Open [src/bytes.rs](../src/bytes.rs) — the smallest, most important file; you
  can now read every line (lifetimes, `Result`, `checked_add`, slices).
- Then [src/analysis/flows.rs](../src/analysis/flows.rs) — newtype invariant,
  enums, iterators, the `Observe` trait, all together.
- For the language itself beyond this codebase: *The Rust Book*
  (doc.rust-lang.org/book) chapters 4 (ownership), 10 (generics/traits/
  lifetimes), and 13 (closures/iterators) cover the foundations above.
