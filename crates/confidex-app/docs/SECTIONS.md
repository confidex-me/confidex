# Field sections

Sections are encrypted presentation metadata on an ordinary Record. They do not
add an entry type or a persistent field identifier. Fields keep their independent
names, values and order.

`Record.extra["confidex.sections"]` contains a map with `version = 1` and a
`groups` array. Each group has `name`, `start` and `count`. The span addresses
entry positions in that revision. Groups are ordered, do not overlap and can
be empty. Names can be empty or repeat. This client accepts at most 512 groups
and 4,096 UTF-8 bytes per name.

The draft maps these spans to expanded legacy fields. Its `source` index only
binds a group to its original metadata in the verified revision. It is not
written to the Record. Saving preserves unknown map keys and updates spans
after field edits. Renaming or moving a section does not create new field IDs.
Ungrouping removes its presentation boundary and keeps every field value.

When explicit layout metadata is absent, named 1PUX sections are read from
`confidex.import.section` on entries. The original import metadata remains.
An explicit empty layout prevents removed import groups from reappearing.
Unsupported versions and malformed layouts remain opaque: ordinary field edits
preserve them, and this client does not replace them with an empty layout.

Section metadata participates in the whole compressed Record size check.
Saving appends a signed revision; existing signed bytes are not changed.
