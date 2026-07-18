# M2–M8 fault-injection matrix

The following cases are required for release verification. Focused unit and
integration tests cover the portable rows on every change; the Btrfs rows run
only in the privileged VM capability job.

| Boundary | Injected event | Required recovery result | Coverage |
| --- | --- | --- | --- |
| Import | source repository removed after Ready snapshot | retained tag, commit, tree, and blobs resolve from cold storage | portable integration test |
| Cold record | truncated/corrupt payload, header, footer, or tail | invalid data is rejected; only a valid open prefix remains usable | portable store/format tests |
| Cold chunk seal | crash after footer sync, after rename/directory sync, or after catalog publication | startup validates the footer, completes or republishes the sealed state idempotently, and never makes the chunk writable again | portable store tests |
| Cold chunk rotation | target crossed or one record exceeds the target | every record remains whole; an oversized record occupies one sealed dedicated chunk | portable store tests |
| Cache hydrate | concurrent same-ContentId requests | one authoritative read/publish; all callers receive the verified file | portable cache test |
| Cache hydrate | corrupt/incomplete cache leaf or malicious symlink | no invalid file is accepted; leaf is quarantined or regenerated without following links | portable cache test |
| Checkout | malformed Git path or concurrent symlink substitution below staging | no path escapes staging and no partial workspace is published | portable checkout test |
| Workspace | crash between manifest and Ready catalog batch | manifest is not visible as Ready; reconciliation can safely inspect it | portable workspace manifest test |
| Daemon job | crash with a Running record or temporary record | running work returns to Queued and temporary files are removed | portable daemon test |
| Generation GC | reader lease held while retirement begins | new leases stop; old generation remains until the last lease drains | portable maintenance test |
| Generation publication | pointer update fails after catalog batch | catalog generation remains authoritative and startup repairs the pointer | portable maintenance test |
| Backup | corrupt descriptor/manifest or restore destination exists/is unsafe | restore fails before publication and target is unchanged | portable backup test |
| Backup → checkout | original cold tree removed after checkpoint, then restored | restored chunk bytes hydrate and materialize a raw workspace without the original tree | portable workspace integration test |
| Loop attach | reboot-style pre-existing loop association | helper verifies canonical backing image then reuses it; no duplicate loop is attached | privileged VM |
| Btrfs init | existing or unmarked image path | no formatting or truncation occurs | privileged VM |
| Btrfs mount | wrong UUID, label, marker, or mountpoint | helper rejects the mount without formatting | privileged VM |
| Btrfs FICLONE | mutation after clone | source bytes remain unchanged | privileged VM and runtime probe |
| Image grow | failure after file growth, loop capacity refresh, or guest resize | daemon reports a distinct incomplete grow and verifies before admitting work | privileged VM |

The privileged suite is intentionally not enabled on an ordinary GitHub-hosted
runner: it needs an isolated Btrfs scratch device, loop support, and mount
capability. It must be run before release on a dedicated VM.
