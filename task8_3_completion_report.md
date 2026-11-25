# Task 8.3 Completion Report: Convert and Build the 1,000-Email Development Dataset

**Project**: Multi-Agent AI Phishing Email Detector  
**Date**: November 12, 2026  
**Task**: 8.3 Convert and Build the 1,000-Email Development Dataset  
**Status**: COMPLETE (Verified against all 12 acceptance criteria)  

---

## Executive Summary

Task 8.3 has been completed in full compliance with the approved specification. The 1,000-email development dataset has been converted, filtered, deterministically sampled, deduplicated, and verified on disk. All 1,000 individual EML files exist under `data/dev/eml/`, fully indexed across comprehensive CSV, JSONL, and summary manifests under `data/dev/manifests/`.

Raw source archives were preserved read-only without byte modification. UW IMAP mailbox internal folder control records were identified and excluded. Authentication headers were passively detected for presence without inferring verification pass/fail status or querying remote DNS/mail services. Zero raw or development email data is tracked in Git.

---

## 1. Final Dataset Composition & Category Counts

The development dataset contains exactly 1,000 distinct email messages across the approved categories:

| Category | Source Archive | Label Assigned | Target Count | Actual Count | Status |
|---|---|---|---:|---:|:---:|
| **Easy Ham** | `20030228_easy_ham.tar.bz2` | `ham_easy` | 500 | 500 | MATCH |
| **Hard Ham** | `20030228_hard_ham.tar.bz2` | `ham_hard` | 250 | 250 | MATCH |
| **Phishing** | `phishing-2015.mbox` & `phishing-2021.mbox` | `phishing` | 250 | 250 | MATCH |
| **TOTAL** | — | — | **1,000** | **1,000** | **MATCH** |

> **Label Integrity Rule**: As required, SpamAssassin ham messages are strictly assigned `ham_easy` and `ham_hard` labels. They are **not** labeled as confirmed legitimate.

---

## 2. Phishing Source-Year Breakdown

Phishing candidates were sourced exclusively from the approved modern Nazario archives (`phishing-2015.mbox` and `phishing-2021.mbox`). Historical archives (`phishing0.mbox`) were excluded from development dataset sampling.

### Usable Candidate Counts & Proportional Allocation
- **`phishing-2015.mbox`**:
  - Total MBOX keys: 307
  - UW IMAP internal control record (key 0): 1 excluded
  - Windows Defender host AV quarantine (`stage_phish_2015_000279_1a70855aa133.eml`): 1 inaccessible
  - Usable accessible candidates: **305**
- **`phishing-2021.mbox`**:
  - Total MBOX keys: 101
  - UW IMAP internal control record (key 0): 1 excluded
  - Usable accessible candidates: **100**
- **Total Usable Phishing Candidates**: **405**
- **Proportional Allocation**:
  - 2015 Target: $\text{round}(250 \times \frac{305}{405}) = 188$
  - 2021 Target: $250 - 188 = 62$

| Year | Archive | Usable Candidates | Sampled Count | Percentage |
|---|---|---:|---:|---:|
| **2015** | `phishing-2015.mbox` | 305 | **188** | 75.2% |
| **2021** | `phishing-2021.mbox` | 100 | **62** | 24.8% |
| **Total** | — | **405** | **250** | **100.0%** |

---

## 3. Conversion and Exclusion Statistics

### UW IMAP Internal Mailbox Folder Control Records
UW IMAP internal mailbox state records were conservatively identified and excluded from staging and dataset selection:

1. **`phishing-2015.mbox` (Key 0)**:
   - Reason: UW IMAP internal mailbox folder data record (`FOLDER INTERNAL DATA`)
   - Subject: `DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA`
   - From: `Mail System Internal Data`
   - SHA-256: `d09fc1572173eb7ecbd6d8ff0e2cc47229452af5816caffee58e4ecc572276b9`
   - Size: 500 bytes
   - Status: `EXCLUDED_INTERNAL_RECORD`
2. **`phishing-2021.mbox` (Key 0)**:
   - Reason: UW IMAP internal mailbox folder data record (`FOLDER INTERNAL DATA`)
   - Subject: `DON'T DELETE THIS MESSAGE -- FOLDER INTERNAL DATA`
   - From: `Mail System Internal Data`
   - SHA-256: `85bd3c36d97f2f8fd0158b33e8691d81805048dbd8a996faa1b9f8bb45aaaf6d`
   - Size: 489 bytes
   - Status: `EXCLUDED_INTERNAL_RECORD`

> Ordinary emails discussing folder data, system notices, or containing similar text in body or subject without matching the specific UW IMAP header signature were preserved and tested.

### Conversion Pipeline Summary
- **Candidate emails staged**: 3,157 records
  - `easy_ham`: 2,501 candidates
  - `hard_ham`: 251 candidates
  - `phishing_2015`: 305 candidates
  - `phishing_2021`: 100 candidates
- **Total excluded internal records**: 2 records
- **Failed conversions**: 0
- **Shortfall status**: NONE (all candidate pools comfortably exceeded targets)

---

## 4. Deduplication & Collision Protection

- **SHA-256 Content Deduplication**:
  - All 1,000 selected EML files have unique SHA-256 digests.
  - Duplicate content hashes in final dataset: **0**.
- **Message-ID Deduplication**:
  - All sampled messages have unique Message-IDs (or synthetic deterministic keys for missing Message-IDs).
  - Duplicate Message-IDs in final dataset: **0**.
- **Atomic Collision Protection**:
  - File writing uses `mode="xb"` via `write_eml_file()`.
  - Accidental silent overwriting of existing output files is prohibited and raises `FileExistsError` unless `--overwrite` is explicitly specified.

---

## 5. Manifest Locations and Structure

Dataset manifests and summaries are stored under `data/dev/manifests/`:

1. **`data/dev/manifests/dev_manifest.csv`**:
   - Tabular manifest containing all 1,000 selected samples with complete provenance headers.
2. **`data/dev/manifests/dev_manifest.jsonl`**:
   - JSONL format containing 1,000 JSON records (one line per selected email).
3. **`data/dev/manifests/conversion_manifest.jsonl`**:
   - Full audit trail of all 3,159 inspected source messages (3,157 candidates + 2 excluded records).
4. **`data/dev/manifests/dev_dataset_summary.json`**:
   - High-level metric summary including candidate counts, final category counts, exclusion records, authentication counts, and sampling parameters.

### Documented Metadata Schema per Sample
Each manifest entry records:
- `sample_id` (e.g. `DEV_000001_EASY_HAM`)
- `source_dataset` (`spamassassin` or `nazario`)
- `source_archive` (e.g. `20030228_easy_ham.tar.bz2`, `phishing-2015.mbox`)
- `source_year` (`2003`, `2015`, `2021`)
- `original_mbox_key` or `source_message_identifier`
- `assigned_label` (`ham_easy`, `ham_hard`, `phishing`)
- `source_category` (`easy_ham`, `hard_ham`, `phishing`)
- `relative_eml_path` (e.g. `eml/ham_easy/easy_ham_000001_2411e5ae5d65.eml`)
- `sha256` (64-character hexadecimal digest of exact EML bytes)
- `byte_size`
- `conversion_status` (`SUCCESS` or `WARNING`)
- `duplicate_content_hash` (`False`)
- `duplicate_message_id` (`False`)
- `auth_headers_present` (`dkim_signature`, `authentication_results`, `received_spf`, `arc`)
- `warnings`

> **Privacy Guarantee**: No full email bodies, PII, personal phone numbers/passwords, or sensitive header authorization tokens are exposed in the manifest.

---

## 6. Deterministic Sampling & Reproducibility

- **Random Seed**: `42`.
- **Sampling Algorithm**: Deterministic sampling using `random.Random(42).sample()` over sorted candidate SHA-256 digests.
- **Repeatability**: Running the dataset builder with seed `42` yields the exact identical 1,000 samples, preserving source-year phishing distribution and category proportions byte-for-byte.

---

## 7. Authentication-Header Observations

In accordance with strict boundary requirements, authentication headers were checked purely for presence as raw evidence. **No verification results were inferred**, no DNS queries were made, and no remote mail systems were contacted.

### Presence Counts in the 1,000-Email Dataset:
- **`DKIM-Signature` present**: 53 emails (5.3%)
- **`Authentication-Results` present**: 230 emails (23.0%)
- **`Received-SPF` present**: 22 emails (2.2%)
- **`ARC-*` headers present**: 2 emails (0.2%)

### Essential Distinctions Enforced:
1. `DKIM-Signature` presence confirms only that a signature block exists; it does **not** indicate that the signature is valid or passes cryptographic checks.
2. `Authentication-Results` contains an unverified receiving-server assertion; it is **not** treated as ground-truth verdict without downstream policy validation.
3. Missing authentication headers remain explicitly distinguishable from authentication failure.
4. No SPF/DKIM/DMARC evaluation was conducted.

---

## 8. Test Verification Results

All tests across unit, integration, regression, and raw verification suites pass:

### 1. Dataset & Conversion Tests (`tests/test_convert_mbox_to_eml.py`)
```text
============================= test session starts =============================
platform win32 -- Python 3.11.9, pytest-8.3.5
rootdir: C:\Users\laxma\Documents\Mini_Project\Multi-Agent-AI-Detector\phishing-detector
collected 41 items

tests/test_convert_mbox_to_eml.py::TestMboxConverter::... (13 tests)   PASSED
tests/test_convert_mbox_to_eml.py::TestCliInterface::... (3 tests)     PASSED
tests/test_convert_mbox_to_eml.py::TestPrepareDevDataset::... (2 tests) PASSED
tests/test_convert_mbox_to_eml.py::TestNewlineHandling::... (3 tests)  PASSED
tests/test_convert_mbox_to_eml.py::TestFileCollisionProtection::... (2 tests) PASSED
tests/test_convert_mbox_to_eml.py::TestAllDatasetShortfallScenarios::... (3 tests) PASSED
tests/test_convert_mbox_to_eml.py::TestMboxrdEscapingInvestigation::... (2 tests) PASSED
tests/test_convert_mbox_to_eml.py::TestSingleMessageMultipleMessageIds::... (1 test) PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_01_uw_internal_record_is_excluded PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_02_ordinary_email_with_similar_subject_or_body_retained PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_03_correct_source_category_and_labels PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_04_exact_500_250_250_sampling PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_05_deterministic_repeated_sampling_with_seed_42 PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_06_no_duplicate_hashes_in_final_output PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_07_source_year_allocation_is_reproducible PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_08_missing_or_malformed_source_records_handled_safely PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_09_output_collisions_do_not_overwrite_existing_files PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_10_manifest_entries_match_actual_eml_files PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_11_authentication_header_presence_distinguished_from_verification PASSED
tests/test_convert_mbox_to_eml.py::TestTask83DatasetCreation::test_12_shortfalls_stop_dataset_creation_without_synthetic_data PASSED

============================= 41 passed in 21.66s =============================
```

### 2. Raw Dataset Verification Tests (`tests/test_verify_raw_datasets.py`)
```text
============================= test session starts =============================
collected 22 items
============================= 22 passed in 7.52s ==============================
```

### 3. Full Project Test Suite (`pytest -v`)
```text
============================= test session starts =============================
collected 413 items
...
============================ 413 passed in 44.49s =============================
```

---

## 9. Git Privacy & Storage Verification

- `.gitignore` verification:
  ```text
  .gitignore:50:data/dev/   data/dev/
  .gitignore:51:data/raw/   data/raw/
  ```
- Neither raw archives (`data/raw/`) nor development emails and manifests (`data/dev/`) are tracked or staged in Git.
- `git status` verifies no `.eml`, `.mbox`, or `.tar.bz2` files appear in tracked changes.

---

## 10. Limitations and Boundary Observations

1. **Temporal Discrepancy in Authentication Headers**:
   - SpamAssassin ham originates from 2002–2003, before the standardization of DKIM (RFC 4871/6376 in 2007/2011) and DMARC (RFC 7489 in 2015). Consequently, SpamAssassin emails almost completely lack modern cryptographic signatures, whereas Nazario 2015–2021 emails contain them more frequently. Downstream feature extractors must account for this temporal reality rather than treating missing authentication headers as indicative of spam/ham in historical corpora.
2. **Host Antivirus Dynamic Interactions**:
   - On Windows environments with active endpoint protection (Windows Defender), live heuristic detection can flag and quarantine extracted phishing samples on disk (such as `PWS:HTML/Phish.QA` inside sample 279 of `phishing-2015.mbox`). The pipeline incorporates disk accessibility verification to ensure only uncorrupted, unquarantined files are included in usable pools.
3. **No Synthetic Augmentation**:
   - Had deduplication or corruption caused any shortfall below target counts, the pipeline would halt immediately. No synthetic or generated data was used.

---

## Scope Adherence Confirmation

- **No ML models trained**: Verified.
- **No agents built**: Verified.
- **No Logistic Regression meta-classifier created**: Verified.
- **Approved ingestion schemas & extractors unmodified**: Verified.
- **No additional datasets downloaded**: Verified.
- **Approved sampling targets strictly adhered to**: Verified (500 easy_ham, 250 hard_ham, 250 phishing).
- **Task 8.4 not started**: Standing by for explicit user approval.
