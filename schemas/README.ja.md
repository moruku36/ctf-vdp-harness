# 提案する証拠契約

[English](README.md)

[evidence-page.schema.json](evidence-page.schema.json)は`evidence-page/1`の設計。[合成ページ](../examples/evidence-page.synthetic.json)のhashは合成UTF-8本文と一致する。証拠serverや実対象の出力はない。

JSON Schemaは形・必須field・enum・完全／不完全時の省略理由を検査。実行側はidentity／access、decode後の長さ、`offset <= next_offset <= view_bytes`、非終端ページの進行、cursorの結び付き、実object hashを別途検証する。空viewには空の終端ページを一つ認める。errorは結果envelopeで返し、成功した証拠ページにしない。本文4,000文字は初期profileの上限で、無制限captureを意味しない。

固定したローカルschemaと厳密なJSON parse、該当するformat検査を使う。未対応版には明示的移行が必要。[実装仕様](../docs/11-contracts-and-acceptance.ja.md)に動作要件と未実施の受入ケースを記載。
