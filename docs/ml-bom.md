# ML-BOM for the self-hosted model weights (governance item G-7)

The report (Part VI, section 16; Part X, G-7) requires that the weights behind the self-hosted
DeepSeek and Nemotron endpoints are recorded in a CycloneDX 1.6 or later ML-BOM with their source,
hashes and licence, that the BOM is signed (cosign or NGC), and that only safetensors is loaded.
This document describes how the prototype does it and why the two production entries are still
pending in this repository.

## 1. Pieces

| piece | role |
|---|---|
| `sbom/models.yaml` | manifest the platform team fills: one entry per self-hosted model (`model_id` = the `model` field in `config/mara.yaml`), official source, licence, format, serving stack, signature method, per-file SHA-256 |
| `scripts/ml_bom.py` | `hash-dir`, `build`, `validate`, `verify`, `verify-signature`, `sign-command`, `check` |
| `src/mara/mlbom.py` | the library behind the script, policy P7, the pipeline's audit entry and governance check G-7 |
| `sbom/ml-bom.cdx.json` | the ML-BOM built from the manifest (committed; CI rebuilds it and fails on drift) |
| `src/mara/groundtruth/cyclonedx/` | vendored CycloneDX 1.6 JSON schema (`bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json`) used by `validate` and the tests |
| policy P7 `ml-bom` | with `ml_bom.required: true`, every `openai_compatible` model must have a complete component; with `require_signature: true`, the Sigstore bundle must exist |
| `sbom/examples/ml-bom.example.cdx.json` | a complete component built from two synthetic stand-in files (labelled `mara:example`), used by `config/examples/ml-bom-required.yaml` and the tests; not real weights |

## 2. What a complete component looks like

Each self-hosted model is a `machine-learning-model` component:

- `name`, `version`, `licenses` (SPDX id when one exists, else the licence name);
- `hashes`: one SHA-256, the digest of the sorted `sha256  path` lines of every file (the same
  text `sha256sum` prints), so the component hash changes when any file changes;
- nested `components` of type `file`, one per file, each with its SHA-256 and size;
- `externalReferences`: `distribution` (where the weights were downloaded from), `vcs`, `license`;
- `modelCard.modelParameters` (`architectureFamily`, `modelArchitecture`);
- `properties` under the `mara:` prefix: `model-id`, `family`, `format` (always `safetensors`),
  `serving` (`vllm` or `nim`), `signature` (`cosign-keyless` or `ngc`, plus identity, issuer and
  bundle path), `status` (`complete` or `pending`), `file-count`, `note`.

`component_problems()` lists what is missing; a component is complete only when the list is empty.
Pickle-based checkpoints (`.bin`, `.pt`, `.pth`, `.pkl`, `.pickle`, `.ckpt`) are refused both when
hashing a directory and when they appear in a BOM, so a BOM cannot bless a pickle file.

## 3. Procedure for the platform team

1. Download the weights from the official source only (the `source.url` in the manifest) and pin
   the revision. For NGC-distributed models keep NGC's own signature check on the download host.
2. On that host:

   ```
   python3 scripts/ml_bom.py hash-dir /srv/models/deepseek-v3.2 --model-id deepseek-v3.2 --write-manifest sbom/models.yaml
   ```

   or paste the registry's per-file sha256 values (Hugging Face exposes them as the LFS object id)
   into `files:`. Fill `source.revision`, `signature.identity` and `signature.issuer`.
3. Build and validate:

   ```
   python3 scripts/ml_bom.py build --manifest sbom/models.yaml --out sbom/ml-bom.cdx.json
   python3 scripts/ml_bom.py validate --bom sbom/ml-bom.cdx.json --manifest sbom/models.yaml
   ```

   `build` refuses a pending entry unless `--allow-pending` is given, which is how the committed
   BOM was produced.
4. Sign the BOM with the locked cosign (keyless, interactive OIDC flow):

   ```
   python3 scripts/ml_bom.py sign-command --bom sbom/ml-bom.cdx.json
   ```

   prints `cosign sign-blob --bundle sbom/ml-bom.cdx.json.sigstore.json sbom/ml-bom.cdx.json`.
   Commit the bundle next to the BOM.
5. In `config/mara.yaml` set `ml_bom.required: true`, `require_signature: true`,
   `certificate_identity` and `certificate_oidc_issuer`. From then on policy P7 refuses the
   configuration when a self-hosted model has no complete component or the bundle is missing, and
   governance check G-7 turns green.
6. On every inference host, before serving:

   ```
   python3 scripts/ml_bom.py verify-signature --bom sbom/ml-bom.cdx.json --bundle sbom/ml-bom.cdx.json.sigstore.json \
       --certificate-identity <identity> --certificate-oidc-issuer <issuer>
   python3 scripts/ml_bom.py verify --bom sbom/ml-bom.cdx.json --model-id deepseek-v3.2 --weights /srv/models/deepseek-v3.2
   ```

   `verify` re-hashes the directory and reports files missing on disk, files not in the BOM, hash
   mismatches and a component digest that no longer matches its own file list.

## 4. What the review records

The pipeline reads the BOM at start-up and writes one entry per self-hosted model into the report's
bias audit (`ml_bom`: model id, status, component name and version, digest); `report.md` shows it
under "Model provenance". A report therefore states which weights, by hash, produced it once the
BOM is complete, and says `pending` until then.

## 5. Why the production entries are pending here

This repository does not host the weights, and the environment the prototype was written in could
not reach huggingface.co, hf-mirror or NGC to fetch registry hashes. The manifest therefore carries
the source and licence for DeepSeek-V3.2 (GitHub repository, MIT; the formal source of the V4
weights could not be confirmed, report Appendix B item A78) and Nemotron 3 Super (NVIDIA Open Model
License; exact repository and licence text still to be confirmed, B-gap-9) with empty `files:`.
The BOM is built with `--allow-pending`, its components are marked `mara:status=pending`, policy P7
reports them, and governance check G-7 fails naming both models and the procedure above. No
placeholder hash was written anywhere; hashes appear only once someone has computed them.

## 6. Schema provenance

The three schema files were fetched on 2026-09-12 from
`https://raw.githubusercontent.com/CycloneDX/specification/master/schema/` (the GitHub API to pin a
commit was not reachable from the authoring environment). SHA-256 of the vendored files:

| file | sha256 |
|---|---|
| `bom-1.6.schema.json` | `18f57f7482593bad9f21b4feed09084640cbeff419d62ad5090c5ceccca5b37d` |
| `spdx.schema.json` | `ea6e844ee6fba1e93473d94834d0ee0996970533497935f932f73d488ffdf4a3` |
| `jsf-0.82.schema.json` | `8bae002c25e723db7ee1f26afde680ae1a2b1a8f6b4b4b0fd65dc3becb090aae` |

`validate` uses `jsonschema` (a dev dependency) with the two `$ref` targets resolved to the vendored
copies, so validation never fetches anything.

## 7. Verification

`tests/test_ml_bom.py` covers hashing (pickle refused, safetensors required), the manifest round
trip, schema validity of the built BOM, `component_problems` for each missing piece, `verify` on a
tampered and on an extra file, the cosign command line against a fake cosign in `MARA_TOOLS_DIR`,
policy P7 in its three states, governance G-7 on this repository (FAIL naming both pending models)
and on a repository with a complete BOM (PASS), and the pipeline's audit entry.
