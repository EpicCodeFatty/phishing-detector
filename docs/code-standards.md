# Code standards

These apply to all Python in this repository. They exist so that someone reading this project for the
first time can navigate it quickly, and so that style is never a thing to argue about.

The principles below are drawn from PEP 8 and PEP 257, *Code Complete 2* (McConnell), *The Pragmatic
Programmer* (Hunt & Thomas), *Refactoring* (Fowler) and *Clean Code* (Martin). Where those sources
disagree, the deciding question is always the same: will the next person understand this without
asking?

---

## 1. Naming

Names are the main documentation. A good name removes the need for a comment.

- `lower_snake_case` for modules, functions and variables; `CapWords` for classes; `UPPER_SNAKE` for
  module-level constants. (PEP 8)
- A function name states what it *does*, in verb form: `classify_domain`, `extract_hostname`,
  `build_result`. Not `handle`, `process`, `do_check`.
- A boolean name reads as a question: `has_headers`, `is_shortener`, `looks_like_brand`.
- No abbreviations except ones universally understood in context (`url`, `html`, `tld`). Write `message`
  rather than `msg`, `attachment` rather than `att`.
- The length of a name should match the size of its scope. A loop counter can be `i`; a module-level
  constant cannot.
- Do not encode the type in the name: `urls`, not `url_list`. Type hints already say that.

## 2. Functions

- **One job per function.** If describing what it does needs the word "and", it is two functions.
- **Guard clauses, not nesting.** Return early on the uninteresting cases so the main path stays at the
  left margin:

  ```python
  # Preferred
  def check_href(anchor: Anchor) -> Finding | None:
      host = hostname_of(anchor.href)
      if host is None:
          return None
      if not anchor.text:
          return None
      ...

  # Avoid
  def check_href(anchor):
      host = hostname_of(anchor.href)
      if host is not None:
          if anchor.text:
              ...
  ```

- **Nesting depth of two, at most.** Deeper than that means a helper is waiting to be extracted.
- **Around twenty lines** is a useful signal, not a law. A longer function is fine when it is a flat
  sequence of steps; a six-line function with four levels of nesting is worse than a thirty-line one
  that reads top to bottom.
- **Arguments: three or fewer.** Past that, pass a dataclass. This is why the checks take a
  `ParsedEmail` rather than eight separate fields.
- **No output arguments.** A function returns its result; it does not mutate a list it was handed.

## 3. Purity and side effects

The engine is a pure function, and that is a deliberate architectural property rather than an accident.

- Check functions read a `ParsedEmail` and return findings. They do not perform I/O, do not read
  environment variables, do not log, and do not mutate their input.
- All I/O lives at the boundary: `detect.py` for the CLI, `web.py` for HTTP, `db.py` for the database.
- This is what makes the engine testable without fixtures, mocks or a network, and it is what makes the
  verdict reproducible for the same input.

## 4. Type hints

- Every public function is fully annotated, arguments and return value. (PEP 484)
- Prefer the modern syntax: `list[Finding]`, `str | None`, not `List[Finding]`, `Optional[str]`.
- Internal one-line helpers may go unannotated if the types are obvious from two lines of context.

## 5. Docstrings

Follow PEP 257.

- One line for a function whose name and signature already explain it.
- A multi-line docstring where the contract is not obvious: what it returns, what it does with bad
  input, and anything surprising.
- Every `check()` function gets a docstring naming what it detects and listing the finding codes it can
  produce, so the engine's behaviour can be read without reading its logic.

```python
def check(email: ParsedEmail) -> list[Finding]:
    """Inspect links in the message body.

    Produces: href_mismatch_brand, ip_url, href_mismatch, punycode_url,
    shortener, suspicious_tld.

    At most one finding per code; the first occurrence is reported as evidence.
    """
```

## 6. Comments

- A comment explains **why**, never **what**. The code already says what.
- A comment is warranted for a decision, a trade-off, a non-obvious constraint, or a workaround.
  `suffix_list_urls=()` needs a comment explaining that it disables network access. `i += 1` does not.
- Delete commented-out code. Git remembers it.
- A comment that restates the line above it is noise, and worse, it is noise that goes stale.

## 7. No magic values

Every threshold, weight, keyword list and file extension lives in `lists.py` or as a named module
constant. A reviewer should be able to read the engine's judgement without reading any logic, and
should be able to change a threshold in one place.

```python
# Good
if score >= THRESHOLDS["phishing"]:

# Bad
if score >= 60:
```

## 8. Error handling

- **Inside the engine, never raise.** A check that cannot evaluate something returns no finding for it.
  Malformed input is the normal case for this tool, not an exceptional one.
- **Catch specific exceptions.** `except ValueError:`, never a bare `except:` and never
  `except Exception:` unless it is at a boundary and the exception is logged.
- **Fail loudly at the edges.** The CLI prints a clear message and exits with a non-zero code; the web
  layer returns a 4xx or 5xx and logs. Silence belongs only inside the checks.
- Do not use exceptions for control flow.

## 9. Duplication

DRY is about duplicated *knowledge*, not duplicated characters. Two checks that both call
`hostname_of()` are not duplication; two places that both hard-code the list of dangerous extensions
are.

Extract a helper when the same decision appears twice. Do not build an abstraction on a single use:
premature abstraction costs more readability than the duplication it prevents.

## 10. Imports

- Three groups, separated by a blank line: standard library, third party, local. (PEP 8)
- No wildcard imports.
- No imports inside functions, except to break a genuine circular dependency, and then with a comment
  saying so.

## 11. Formatting is automated

Style is not discussed; it is applied by a tool.

```bash
pip install ruff
ruff format .          # formats
ruff check . --fix     # lints and fixes what it can
```

`pyproject.toml`:

```toml
[tool.ruff]
line-length = 100
target-version = "py312"

[tool.ruff.lint]
select = ["E", "F", "I", "B", "UP", "SIM"]
# E/F: pycodestyle and pyflakes, the baseline
# I:   import order
# B:   bugbear, catches real bugs like mutable default arguments
# UP:  modern syntax for the target Python version
# SIM: simplifications that reduce nesting
```

Run both before every commit. `ruff check` passing cleanly is part of "done".

## 12. Tests

- One test asserts one behaviour.
- The test name is a sentence describing that behaviour:
  `test_lookalike_domain_detects_digit_substitution`, not `test_sender_1`.
- Arrange, act, assert, with a blank line between the three.
- Table-driven tests for rule sets, so that adding a case is adding one line:

  ```python
  @pytest.mark.parametrize("domain,expected_code", [
      ("paypal.com",         None),
      ("paypalobjects.com",  None),
      ("paypa1.com",         "lookalike_domain"),
      ("paypal-secure.com",  "brand_in_domain"),
  ])
  def test_classify_domain(domain, expected_code):
      ...
  ```

- Tests are read more often than they are run. They document the intended behaviour, so they get the
  same care as the code.

## 13. What "done" means for a module

1. `ruff format` and `ruff check` are clean.
2. Public functions have type hints and docstrings.
3. Tests cover the positive case, the negative case, and malformed input.
4. No magic values, no commented-out code, no `TODO` without a name attached to it.
5. Someone who has not read the design document can tell what the module does from its first screen.

---

## A note on the sources

These principles are widely agreed on, but they are not scripture, and it is worth knowing where the
disagreement lies.

*Clean Code* is the most quoted book here and also the most criticised: its specific prescriptions
(functions of four lines, no arguments where possible) are generally considered dogmatic, and several
of its own examples are poor. Its durable contributions are the emphasis on naming and the rule that
comments explain intent.

*Code Complete 2* is the more careful book, and the one that cites actual research on defect rates and
routine length. Where the two conflict, prefer McConnell.

*The Pragmatic Programmer* contributes DRY and orthogonality, both of which are about coupling rather
than about style.

*Refactoring* matters less for writing new code than for the vocabulary it gives you — "long method",
"feature envy", "primitive obsession" — which is useful for naming a problem in review.

For Python specifically, PEP 8 and PEP 257 are the standard, and *Fluent Python* (Ramalho) is the
reference for writing code that reads as Python rather than as translated Java.
