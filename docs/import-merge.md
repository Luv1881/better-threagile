# Re-import merge (`--merge`)

`threagile import <drawio|threat-dragon|otm|mermaid> --merge existing-model.yaml`
reconciles a fresh diagram import against a model file you have already
hand-edited, instead of overwriting it. This is the workflow for "the diagram
changed, but I already reviewed/renamed/retyped half of it" — a single-shot
import would either clobber your edits or force you to redo them by hand.

## Ownership signal: tags, not comments

The importer marks every element it generates with a `review-<importer>` tag
(e.g. `review-drawio`) — or `stub-data-asset` for stub data assets (see
[docs/import-scaffold.md](./import-scaffold.md)). `--merge` uses **the
presence of that tag, and nothing else,** to decide who owns an element:

- **Tag still present → importer-owned.** Nobody has finished reviewing this
  element yet, so the fresh diagram value is authoritative: its fields are
  overwritten with the current parse.
- **Tag removed → user-owned/finalised.** Once you delete the review tag
  (the normal `threagile review` workflow), `--merge` never touches that
  element's fields again. If the diagram's current value disagrees with what
  is in the YAML, a `merge-conflict:<field>` tag is appended instead of
  changing anything, so `threagile review`/`threagile gate` can surface the
  disagreement for you to resolve by hand.

An earlier version of this design considered detecting "has the user
reviewed this" by diffing the `TODO(review)` head-comments the scaffold step
attaches to fields, on the theory that a removed/edited comment means
"reviewed". **That was prototyped and rejected.** A basic round-trip (parse
→ mutate a sibling field via the `yaml.Node` API → re-marshal) does keep a
`HeadComment` attached to the right node — but that isn't the failure mode
that matters for merge. The real requirement is detecting whether *a human,
editing with a real text editor, not through `yaml.Node`* removed or edited
one specific comment. Deleting the commented field, reordering keys, or
just reflowing blank lines around it are all completely normal edits, and
every one of them either orphans the comment onto an unrelated following key
or drops it silently — gopkg.in/yaml.v3 has no concept of "this comment was
intentionally addressed" versus "this comment vanished because the file was
reformatted". Tags don't have this problem: they're real YAML data (a
sequence entry), not something attached to a node by textual position, so
they survive an arbitrary human re-edit and an arbitrary number of
parse/marshal round-trips unambiguously. `--merge` therefore uses the tag
channel exclusively; see `internal/threagile/import_merge.go` for the full
writeup in code.

## Matching: same deterministic IDs the importers already generate

Every element already gets a stable, deterministic ID from the importer
(e.g. `<sourceHint>-<cellID>-<label>` for drawio/threat-dragon, `comp-<id>-otm`
for OTM) — the same diagram element always produces the same Threagile ID.
`--merge` uses that ID as the sole match key for technical assets, data
assets, and trust boundaries: "does an element with this ID already exist in
the YAML" is a lookup, not a fuzzy match.

Communication links are the one exception: the Threagile authoring format
nests links under their source technical asset, keyed by **link title**, and
carries no independent link ID field. `--merge` matches links by
`(source technical asset ID, link title)`, which is deterministic for the
same reason the element IDs are (same diagram edge ⇒ same source ⇒ same
label ⇒ same title) but can, in principle, misfire if you retitle a link by
hand to collide with another link title. This is a known, documented
limitation, not a silent one — see the code comment in `import_merge.go`.

## What happens to each kind of change

| Situation | Result |
|---|---|
| New in diagram, ID not found in existing YAML | Appended as a new element, with the same `review-<importer>` tag and TODO(review) comments a plain import would give it. Always appended to the **main file** (the one passed to `--merge`), never to an included file. |
| Existing element, still importer-owned (review tag present) | Overwritten with the fresh diagram's fields, in whichever file it currently lives in. |
| Existing element, review tag removed (user-owned) | Left untouched. If the diagram disagrees on a field, a `merge-conflict:<field>` tag is appended instead. |
| In existing YAML, absent from the fresh diagram, still importer-owned | Left in place, tagged `merge-absent-from-diagram` so `threagile review`/`threagile gate` can flag it — never deleted. |
| In existing YAML, absent from the fresh diagram, user-owned | Left completely untouched — presumably a hand-added element unrelated to the diagram. |
| No `review-*`/`stub-data-asset` tag found *anywhere* in the target file (or its includes) | Treated as a purely additive merge — nothing existing is ever overwritten, only new-by-ID elements are appended — and a warning is printed to stderr, since this usually means the target was never imported (hand-written model) and there's no ownership signal to trust. |

Only the fields a diagram importer actually sets are ever compared for
conflicts (asset type/technology/machine/encryption/internet-exposure,
trust-boundary type, data-asset confidentiality, link protocol/
authentication) — free-form fields a human might add by hand (`owner`,
`justification_*`, etc.) are never touched or conflict-flagged.

## `includes:`

If the target file (or any file it transitively includes via `includes:`)
already declares an included file, each file is parsed and indexed
independently. A matched element is updated **in the file it was actually
found in** — an element that lives in `assets.yaml` (included from
`model.yaml`) stays in `assets.yaml`. Brand-new elements always land in the
main entry-point file passed to `--merge`, never in an included file, since
there is no way to infer which included file a never-before-seen element
"belongs" in.

## Output

Unlike a plain import, `--merge` ignores `--output`/`--diff` and writes the
reconciled model back **in place** — to the `--merge` path and to any
included file that received an in-place update — printing a one-line
summary (counts of new/updated/conflict/absent elements, plus the list of
files touched) to stdout.

```sh
threagile import drawio --diagram architecture.drawio --merge model.yaml
```
