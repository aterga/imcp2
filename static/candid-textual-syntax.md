# Candid textual syntax (what these tools use)

Every tool here takes and returns **textual Candid** (the `(...)` value syntax,
e.g. `(record { owner = principal "aaaaa-aa"; amount = 5 : nat })`), never the
binary form. This is the value syntax per type. For the full type reference
(subtyping, type syntax, services) read the `candid://reference` resource.

Quick reminders:
- Arguments are always a parenthesised, comma-separated tuple: `()`, `(42 : nat)`, `(a, b)`.
- Record fields use `=`; variants use one tag: `variant { Ok = 5 : nat }`.
- `opt`: `null` or `opt <v>`. `vec`: `vec { a; b }`. Blobs: `blob "\CA\FF"`.
- Annotate numeric types when they matter: `5 : nat64`, `-1 : int8`.

---

### text
``` candid
""
"Hello"
"Escaped characters: \n \r \t \\ \" \'"
"Unicode escapes: \u{2603} is ☃ and \u{221E} is ∞"
"Raw bytes (must be utf8): \E2\98\83 is also ☃"
```


### blob
`blob <text>`

where `<text>` represents a text literal with all characters representing their UTF-8 encoding and arbitrary byte sequences (`"\CA\FF\FE"`).

For more information about text types, see [text](#type-text).


### nat
``` candid
1234
1_000_000
0xDEAD_BEEF
```


### int
``` candid
1234
-1234
+1234
1_000_000
-1_000_000
+1_000_000
0xDEAD_BEEF
-0xDEAD_BEEF
+0xDEAD_BEEF
```


### natN and intN
Same as `nat` for `nat8`, `nat16`, `nat32`, and `nat64`.

Same as `int` for `int8`, `int16`, `int32`, and `int64`.

We can use type annotation to distinguish different integer types.

``` candid
100 : nat8
-100 : int8
(42 : nat64)
```

Canister init arguments passed to `icp` must be explicit with data types, such as:

```
field = 5 : nat64
```


### float32 and float64
The same syntax as `int`, plus floating point literals as follows:

``` candid
1245.678
+1245.678
-1_000_000.000_001
34e10
34E+10
34e-10
0xDEAD.BEEF
0xDEAD.BEEFP-10
0xDEAD.BEEFp+10
```


### bool
`true`, `false`


### null
`null`


### vec t
``` candid
vec {}
vec { "john@doe.com"; "john.doe@example.com" };
```


### opt t
``` candid
null
opt true
opt 8
opt null
opt opt "test"
```


### record \{ n : t, … \}
``` candid
record {}
record { first_name = "John"; second_name = "Doe" }
record { "name with spaces" = 42; "unicode, too: ☃" = true }
record { "a"; "tuple"; null }
```


### variant \{ n : t, … \}
``` candid
variant { ok = 42 }
variant { "unicode, too: ☃" = true }
variant { fall }
```


### func (…) → (…)
Currently, only public methods of services, which are identified by their principal, are supported:

``` candid
func "w7x7r-cok77-xa".hello
func "w7x7r-cok77-xa"."☃"
func "aaaaa-aa".create_canister
```


### service: \{…\}
``` candid
service: "w7x7r-cok77-xa"
service: "zwigo-aiaaa-aaaaa-qaa3a-cai"
service: "aaaaa-aa"
```


### principal
``` candid
principal "w7x7r-cok77-xa"
principal "zwigo-aiaaa-aaaaa-qaa3a-cai"
principal "aaaaa-aa"
```


### reserved
`reserved`


### empty
None, as this type has no values

