# Proposed evidence contract

[日本語](README.ja.md)

[evidence-page.schema.json](evidence-page.schema.json) defines `evidence-page/1`; the [synthetic page](../examples/evidence-page.synthetic.json) contains an exact self-consistent hash of its synthetic UTF-8 content. There is no evidence server or real target output.

JSON Schema checks shape, required fields, enums and complete/incomplete omission reasons. Runtime must separately verify identity/access, decoded length, `offset <= next_offset <= view_bytes`, progress for nonterminal pages, cursor binding and actual object hash. An empty view may have one empty terminal page. Errors use the result envelope; they are not successful evidence pages. The 4,000-character content limit is the initial profile cap, not an unbounded capture policy.

Accept only local pinned schemas, with strict JSON parsing and format checking where applicable. Unknown versions require an explicit migration. See [the implementation specification](../docs/11-contracts-and-acceptance.md) for behavioral requirements and unexecuted acceptance cases.
