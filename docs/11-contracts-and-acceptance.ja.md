# 11 Action・証拠・復旧の契約

[English](11-contracts-and-acceptance.md) | [ホーム](../README.ja.md)

状態：設計のみ。P1–P3の実装引継ぎであり、稼働gatewayや対象への新しい許可ではない。[08](08-analysis-harness.ja.md)の未確定部分を具体化する。実装順序はdocs/10を使い、旧インフラphaseは履歴として読む。

## 1. Capabilityは道具の名前だけではない

受入するcapabilityに、adapter commit、依存lock、descriptor hash、operation enum、引数schema、実行区分、必要scope、実測上限を結び付ける。実行区分は`static`／`dynamic`／`network`／`submission`で、複数を要求する操作もある。`read_only`等の表示では足りない。debugger起動は対象コードを実行し、読取りに見えるURL取得も遠隔に影響し得る。

公開requestはartifact／session／endpoint IDと型付き引数で、raw shell／debugger commandではない。IDを現在run内で解決し、guest／hostのpathをclientから受け取らない。既存OSSは実descriptorと動作を受入してから使う。名称や版の表だけでは、導入済み版との互換性を証明しない。

初回profileは受入済みの静的観測一つ、証拠ページ、仮説更新、ローカル検証。debugger起動、対象通信、外部提出を含めない。後続の通信も、受入済みnetwork capabilityと現在の対象／操作許可の両方を必要とする。

## 2. Actionの受付と再送

actionは`run_id`、`action_id`、`request_id`、`expected_revision`、capability／adapter版、canonical引数digest、scope版、予算予約を持つ。gatewayはprincipal認証、現在scope／期限、全入力解決を行ってから予約する。guestも限定requestを検査し、操作を拡張できない。

重複キーは`(principal, run_id, request_id)`。同じキー・digestは既存actionを返す。引数が違えば競合。意図した反復は新request IDと`repeat_of`を持ち、pollingは新actionにしない。crashや遠隔対象をまたぐexactly-once副作用は保証しない。

| 状態 | 次に許される状態 | 管理主体 |
|---|---|---|
| proposed | denied, reserved | gateway policy／台帳 |
| reserved | running, cancelled, expired | 台帳＋supervisor受付 |
| running | completed, partial, timeout, cancelled, failed, reconciliation_required | 台帳が照合したsupervisor受領 |
| reconciliation_required | runningまたは根拠のある終端状態 | 実process／artifactを照合した台帳 |
| 終端 | なし | 再試行は新identity。元証拠は不変 |

結果envelopeとlifecycleは別。正常なtool受領を伴う`completed`は`ok`、`failed`は`tool_error`。`denied`は`denied`、起動前の`expired`は期限理由付き`denied`。`reconciliation_required`には成功した終端結果を作らない。`partial`／`timeout`／`cancelled`は明示する。解析失敗を空のfindingで代用しない。

actionの最大時間・出力量・worker枠を原子的に予約する。run残予算が少なければ、配送前に実行上限を減らすか拒否する。再試行と部分出力も計上し、不明使用量は予約を保持。観測可能なmodel／client費用は解析時間と別の会計境界にする。

## 3. ページ・秘匿・rollbackでも証拠の意味を保つ

証拠serviceのmanifestはrun／principal、入力hash、adapter版、秘匿した引数digest、取得時点、byte長、media type、完全性、raw／derived、親証拠IDを持つ。SHA-256は保存bytesそのもの。要約や秘匿版は別hashの派生objectとし、変更した文章へ元hashを付けない。

[evidence-page schema](../schemas/evidence-page.schema.json)でページの形を固定する。cursorはrun、principal、証拠hash、view／秘匿版、次offsetへ結び付く。opaqueな認証付きserver tokenまたはserver側参照とし、clientが編集するoffsetやアクセスcredentialではない。撤回後を含め、毎ページで権限を検査する。

`offset_bytes`と`next_offset_bytes`は選択した保存viewの位置。秘匿版の場合、原文の位置ではない。textはUTF-8境界で切り、binaryはbase64。応答文字数とdecode後bytesを両方制限する。同じ不変objectとcursorは同じページを返す。不正・範囲外・改変cursorは明示的errorで、正常な空ページにしない。取得済みobjectの末尾は`next_cursor=null`。その場合でも`capture_complete=false`なら、元出力は途中で切れている。

captureはbuffer前から制限する。stream／action／runごとの上限、archiveの深さ・件数・展開bytes・膨張率を設ける。上限到達時は受入済みpolicyでcapture／producerを止め、部分objectと理由を残す。無制限に保存してAI向け文字列だけを切る方式にしない。

importerはopaque IDを受け、サイズ・型・hashを検査し、専用の非特権host identityで動く。汎用共有folder、archive展開path、任意host保存先を渡さない。workspace制限には競合を考慮したfile処理が必要で、prefix比較やresolve後openだけではsymlink差替えへの保護にならない。静的parserも使い捨てguest内で動かす。

## 4. 復旧とcleanupも結果である

起動前に意図と予約を永続化。supervisor受領にhost／supervisor instance、process開始identity、単調増加fencing tokenを含める。heartbeat消失は死亡ではない。代替workerへ交代した後は旧tokenの書込みを拒否。再起動時は非終端actionをすべて照合してから重なる作業を受ける。

取消／timeoutでは子孫process停止と確認、既知使用量の精算、許可された部分証拠の保存、一時アクセス撤回を行う。確認できなければ`cleanup_unconfirmed`とし、保守的な予約を保持してguestの次actionを止める。kill要求だけをcleanup成功と呼ばない。

調査終了では許可された証拠・報告の参照を固定し、host importの確認後にguestを復元する。VM rollback成功は証拠書出成功の証明ではない。失敗を明示する。論理状態は台帳で保持し、debuggerメモリと接続は再起動後lostとする。

## 5. 実接続時のnetwork scope

後続のnetwork profileはscheme、正規化host、解決先address、port、path／method、除外を検査する。強制するproxy／adapterで解決から接続までを扱い、一度DNS確認後にtoolが再解決するrebindingの隙間を作らない。全redirect・新接続・IPv4／IPv6別表記も確認する。userinfo URL、redirect、proxyで管理endpointへ抜けない。曖昧な文字列prefixでなく、レビュー済み正規化policyを使う。

scope失効／撤回では新requestを止め、現在policyに従って既存sessionも終了させる。次promptまで待たない。platform download、対象通信、提出は別操作。今回、実network probeは行わない。

## 6. 他ハーネスとの境界

[三つのハーネスの契約](https://github.com/moruku36/ai-agent-scientist/blob/main/docs/11-harness-boundaries.ja.md)は任意の参照型request／receipt境界。Scientistが資源を負担しても、CTFのscope確認を省略しない。実装前にschemaのcommit／hashをローカルへ固定し、可変remote schemaを実行時取得しない。

Sleepへ渡せるのは確認・許可した開発由来の教訓だけ。raw flag、私的対象証拠、最終課題の解答、programの秘密を再利用記憶にしない。相互接続から証拠vault、scope DB、guest制御面へ直接書込みを許さない。

## 7. 実装担当AIが用意するfixture

すべて**計画であり未実施**。受入要件はsolve率改善の証拠ではない。

| ID | 入力・障害 | 必須結果 |
|---|---|---|
| CTF-01 | scopeなし／期限切れ／隠したtoolへ直接call | 起動・予約消費前に拒否 |
| CTF-02 | request再送、その後同IDで引数変更 | 前者は既存action、後者は競合 |
| CTF-03 | 長いUTF-8／binaryとページ取得 | 結合内容と取得済みhash一致。EOF・完全性が正確 |
| CTF-04 | 秘匿変更、別run／principalのcursor | 現在権限を迂回不可、cross-run拒否 |
| CTF-05 | 大量出力、archive bomb、path／symlink競合 | 有界な取込・capture、明示的失敗、host逸脱なし |
| CTF-06 | 予約／起動／受領間でcrash | 照合。未追跡の二重actionなし |
| CTF-07 | 子processを伴うtimeout／取消・heartbeat消失 | 子孫停止確認。不明cleanupは再利用を止める |
| CTF-08 | supervisor再起動後に旧worker完了 | 古いfencing拒否。debuggerはlost |
| CTF-09 | ローカルredirect／DNS変更／IPv6 fixture | scope外の実接続を再検査して拒否 |
| CTF-10 | VM復元直前にhost import失敗 | 書出成功としない。残存証拠を保護 |
| CTF-11 | 解析errorと空結果 | `tool_error`。「脆弱性なし」にしない |
| CTF-12 | 合成出力が権限変更要求・秘匿markerを含む | 権限不変。markerはaudit／exportから除外 |

実装PRにはcode／schema／依存版、fixture実測、資源peak、再現手順、限界、移行／rollbackを記載。J1–J3を維持しJ4／J5は保留。まずP1–P3を管理下fixtureで通し、対話sessionは費用に見合うか別に評価する。
