You are generating PHP array entries for a cryptographic algorithm database.
Output ONLY valid PHP array objects.
Keep entries compact, educational, and practical.
**Rules:**
* Keep descriptions short and useful.
* Use markdown in description_md.
* Use REALISTIC examples.
* Examples must feel real-world, not placeholder nonsense.
* Use actual-looking hex values, tokens, filenames, API keys, domains, passwords, messages, certificates, or session  data.
* Avoid fake fields like "randombytes".
* Avoid academic language.
* Avoid overly verbose metadata.
* Focus on helping developers quickly understand:
  * what the algorithm does
  * when to use it
  * what input/output looks like
  * major risks
**Current status:**
```php
[
    "algo" => 242,
    "uuid" => "e7a8de",
    "name" => "aes-gcm"
]
```
**Required structure example:**
```php
[
    "algo" => 242,
    "uuid" => "e7a8de",
    "name" => "aes-gcm",
    "type" => "aead",
    "status" => "active",
    "title" => "AES-GCM",
    "description_md" => "
AES-GCM is a modern authenticated encryption mode based on AES.
It encrypts data and also verifies integrity using an authentication tag.
Commonly used in:
- TLS 1.3
- HTTPS
- VPNs
- APIs
Best for modern applications needing both speed and security.
",
    "mental_model" =>
        "Locked box with tamper seal.",
    "purpose" => [
        "encrypt data",
        "verify integrity"
    ],
    "good_for" => [
        "https",
        "apis",
        "secure storage",
        "network traffic"
    ],
    "avoid_for" => [
        "nonce reuse environments"
    ],
    "pros" => [
        "very fast",
        "widely supported",
        "authenticated encryption"
    ],
    "cons" => [
        "nonce reuse is dangerous"
    ],
    "difficulty" => 2,
    // 1-5
    "security" => 5,
    // 1-5
    "quantum_impact" => "Grover reduces effective security roughly by half.",
    "post_quantum_status" => 1, // 1-5 scale of post-quantum safety where 1 = broken and 5 = post-quantum safe
    "example" => [
        "scenario" =>
            "Encrypting API token",
        "input" => [
            "key" =>
                "b7e151628aed2a6abf7158809cf4f3c7",
            "nonce" =>
                "cafebabefacedbaddecaf888",
            "plaintext" =>
                "sk_live_4f8d92a1"
        ],
        "output" => [
            "ciphertext" =>
                "4c8a9f7e5b12d93f",
            "tag" =>
                "d1a4f0c98b23ef91"
        ]
    ],
    "flow" => [
        "key + nonce",
        "encrypt plaintext",
        "generate auth tag",
        "verify before decrypt"
    ],
    "related" => [
        "chacha20-poly1305",
        "aes-ccm",
        "aes-gcm-siv"
    ]
]
```
Difficulty:
1 = beginner safe
5 = expert only
Security:
1 = broken
5 = modern/recommended
Use concise arrays and concise wording.
Generate entries matching the category and algorithm behavior accurately.
Do not invent impossible properties.
Do not output explanations outside the PHP array.
Also remember to follow the structure and rules strictly and if can present each field of same algo in one line to make it more compact and readable, and also use real-world examples in the "example" field to help developers understand better.
The Description should be more then just a one-liner (can be 140-200 words), but still concise and practical, avoiding academic language. Focus on helping developers quickly grasp what the algorithm does, when to use it, what input/output looks like, and major risks. Use markdown formatting in the description for clarity.
And don't dare generate any none-keyboard characters in the output, only valid PHP array syntax with input and output example strings that look like real-world data (hex values, tokens, filenames, API keys, domains, passwords, messages, certificates, session data, etc.). Avoid placeholders or fake fields. The goal is to create a useful reference for developers.

Input algorithms:

```

```
Input algorithms are attached, and write all in one x.php file and make sure not miss any also, present the data var as the structure is now and do less new lines to make things more compact not reducing the description size

Also strictly follow that, no auto python or any other language or script not acceptable while generating the output, only directly write the things in PHP array format yourself, not using any code generation tools or scripts.

---

## AGENT EXECUTION NOTES — Context Length Failures & Solutions

### Why The Agent Failed Multiple Times

**Root cause: Writing too many entries at once.**

Each PHP array entry is very long (one compact line with 140-200 word description, example data, all required fields). Attempting to write an entire file (e.g. all 60 entries for d.php — Symmetric Block Ciphers) in a single `create_file` call causes the agent to exceed its output context window before finishing. The result is a truncated file that is syntactically broken (PHP not closed, arrays left open mid-entry).

Observed failure pattern:
- Agent attempts `create_file` with all 60 entries at once
- File gets written but cuts off mid-entry (e.g. stops at entry 19 of 60)
- PHP file is syntactically open — `"legacy"`, `"new"`, outer category `]`, `$data`, and `?>` are all missing
- Any subsequent attempt to write the remaining entries the same way fails again for the same reason

**First failure:** b.php was truncated at line 75 mid-entry (pedersen-hash field cut off mid-value). Fixed by appending the completed entry + remaining entries using PowerShell `Add-Content`.

**Second failure:** d.php (60 entries total: 19 active + 25 legacy + 16 new) — attempting all at once caused truncation after the active section.

---

### How The Agent Finished Successfully

**Rule: Write ONE sub-section (active OR legacy OR new) per operation.**

1. **Task 1 — Active section only:** Used `create_file` to write just the `"active" => [...]` block (19 entries). File intentionally left open (no PHP closing).
2. **Task 2 — Legacy section only:** Used PowerShell `Add-Content` to APPEND the `"legacy" => [...]` block (25 entries) to the open file.
3. **Task 3 — New section + PHP closing:** Used PowerShell `Add-Content` to APPEND the `"new" => [...]` block (16 entries) plus the closing `],` `],` `];` `?>`.

**Why `Add-Content` instead of `create_file` for tasks 2 and 3:**
- `create_file` always overwrites the entire file — it cannot append
- PowerShell `Add-Content -Path ... -Value ... -Encoding UTF8` appends to an existing file without touching what is already written
- This allows completing a file across multiple agent turns without re-generating already-written entries

---

### Recommended Approach For All Future Large Files

For any file with more than ~20 entries:

| Step | Tool | Content |
|------|------|---------|
| 1 | `create_file` | `<?php $data = [ "CategoryName" => [ "active" => [ ...entries... ],` (leave open) |
| 2 | PowerShell `Add-Content` | `"legacy" => [ ...entries... ],` |
| 3 | PowerShell `Add-Content` | `"new" => [ ...entries... ], ], ]; ?>` |

Always verify with `(Get-Content 'path/file.php').Count` and check last 5 lines after each step to confirm syntax is intact before moving to the next task.

Never attempt to write more than ~20 entries per operation. When in doubt, split further.
