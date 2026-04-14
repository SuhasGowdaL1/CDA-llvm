```md
# SVF-Style Call Graph + Alias + memcpy Handling (Performance-Aware Plan)

---

## 1. Goal

Build a **pointer-aware, interprocedural call graph** with:

- Points-to analysis
- Alias reasoning (implicit via points-to)
- Indirect call resolution
- Memory operation modeling (including `memcpy`-like behavior)

System must be:
- Sound (over-approximate)
- Scalable (avoid explosion)
- Incremental (only propagate new information)

---

## 2. Core Principle

Call graph + alias info + memory flow are **solved together**.

> Aliasing is NOT computed separately.  
> It is **derived from points-to sets**:
```

alias(x, y) ⇔ P(x) ∩ P(y) ≠ ∅

```

---

## 3. Global Data Structures

### 3.1 Nodes
Assign integer IDs to:
- Pointer variables
- Memory objects (stack, heap, globals, functions)
- Special memory nodes (optional summary nodes)

---

### 3.2 Points-to Map

```

P: NodeID → Bitset<ObjectID>

```

- Bitset / sparse bitset
- Supports:
  - union (OR)
  - delta tracking

---

### 3.3 Constraint Graph (Typed)

```

ADDR:   o → x     (x = &o)
COPY:   y → x     (x = y)
LOAD:   y → x     (x = *y)
STORE:  x → y     (*y = x)
MEMCPY: src → dst (special handling)

```

Maintain forward + reverse edges.

---

### 3.4 Call Graph

```

CG: Function → Set<Function>

```

---

### 3.5 Worklist

```

W: queue<NodeID>

```

---

### 3.6 Auxiliary

```

RF: Reachable functions
ICS: Indirect call sites
FP_Uses: fp → callsites
ResolvedTargets: cs → set<functions>
ProcessedFunctions
ProcessedCallEdges

```

---

## 4. Alias Model

### 4.1 Definition

```

x aliases y if:
P(x) ∩ P(y) ≠ ∅

```

---

### 4.2 No Explicit Alias Graph

Agent MUST NOT build separate alias structures.

Instead:
- Alias queries = bitset intersection
- Alias propagation = naturally handled via constraints

---

### 4.3 Strong vs Weak Updates

#### Strong Update (precise)
```

if |P(p)| == 1:
overwrite object

```

#### Weak Update (default)
```

if |P(p)| > 1:
union into all targets

```

---

## 5. Preprocessing

- Track only pointer variables
- Ignore scalars
- Only include address-taken functions
- Initialize RF = entry points

---

## 6. Constraint Construction

### Standard

```

x = &o     → ADDR(o → x)
x = y      → COPY(y → x)
x = *y     → LOAD(y → x)
*y = x     → STORE(x → y)

```

---

## 7. memcpy / Memory Copy Handling

### 7.1 Basic Model

For:
```

memcpy(dst, src, size)

```

Model as:

```

for each possible object o_src in P(src):
for each possible object o_dst in P(dst):

```
    COPY(o_src → o_dst)
```

```

---

### 7.2 Optimized Summary Model (Recommended)

Instead of full cross product:

```

MEMCPY(src → dst)

```

During propagation:

```

for each o in delta(src):
if P(dst) gains o:
push dst

```

Then treat as:

```

COPY(src → dst)

```

(works when field-insensitive)

---

### 7.3 Pointer-Aware memcpy

If copying structures containing pointers:

- treat memory object as a node
- memcpy propagates **points-to sets of fields implicitly**

---

### 7.4 Performance Rule

DO NOT:
```

iterate full P(src) × P(dst)

```

Use:
- delta propagation
- summary edges

---

## 8. Initialization

```

for each ADDR(o → x):
P(x) = {o}
push x into W

```

---

## 9. Main Fixpoint Loop

```

while W not empty:

```
x = pop(W)
delta = new elements in P(x)

propagate(delta, x)

if x is function pointer:
    resolve_indirect_calls(x)
```

```

---

## 10. Delta Propagation

### COPY

```

for each COPY(x → y):
if P(y) gains delta:
push y

```

---

### STORE

```

for each STORE(x → p):
for each obj in P(p):

```
    if strong update:
        overwrite P(obj)
    else:
        union delta into P(obj)

    if changed:
        push obj
```

```

---

### LOAD

```

for each LOAD(p → x):
for each obj in delta(p):
if P(x) gains P(obj):
push x

```

---

### MEMCPY

```

for each MEMCPY(src → dst):
if dst gains delta(src):
push dst

```

---

## 11. Indirect Call Resolution

Triggered ONLY when P(fp) changes.

```

for each callsite cs using fp:

```
new_targets = P(fp) - ResolvedTargets(cs)

for each function f in new_targets:

    add CG edge

    bind parameters(caller, f)

    if f not in RF:
        add f to RF
        process_function(f)

update ResolvedTargets(cs)
```

```

---

## 12. Function Processing (Lazy)

```

if f not processed:

```
scan body:
    add constraints
    register ICS
    resolve direct calls

initialize ADDR nodes
mark processed
```

```

---

## 13. Parameter Binding

```

COPY(arg → param)
COPY(return_node → receiver)

```

Deduplicate per call edge.

---

## 14. SCC Compression

- Run Tarjan on constraint graph
- Collapse SCCs

Effect:
```

cycle → single node

```

---

## 15. Optimization Rules

### Push Only on Change
```

if new_pts != old_pts:
push

```

---

### Delta Only
Propagate only newly added elements.

---

### Event-Driven Calls
Use FP_Uses(fp), never scan all callsites.

---

### Lazy Expansion
Only reachable functions.

---

### Bitsets
Use fast OR + difference.

---

## 16. Explosion Control

### Thresholding
```

if |P(fp)| too large:
mark TOP

```

---

### Field Insensitivity
Merge object fields.

---

### Memory Summarization
Group stack/heap objects if needed.

---

## 17. Termination

```

stop when:
W empty
no new call edges

```

---

## 18. Output

```

Call Graph CG
Points-to Map P
Alias relation via intersection

```

---

## 19. Key Insight

- Alias = emergent from points-to
- memcpy = bulk COPY constraint
- Call graph = driven by pointer flow

---

## 20. Mental Model

```

Track where pointers can go.
Memory copies move pointer relationships.
Aliases emerge from shared targets.
Resolve calls only when new targets appear.
Never propagate the same information twice.

```
```
