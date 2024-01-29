# Encrypted Container File Performance Analysis

### Setup (Linux)
1. Install Python if not pre-installed
2. `cd <repo>/perf`
3. `python -m venv .venv`
4. `source .venv/bin/activate`
5. `pip install -r requirements.txt`
6. Fix `<repo>/perf/.venv/lib64/python3.12/site-packages/brokenaxes.py` as described in [#102](https://github.com/bendichter/brokenaxes/issues/102#issuecomment-1832827619)
7. Modify LaTeX export function of pandas to produce better tables: Change in `<repo>/perf/.venv/lib64/python3.12/site-packages/pandas/core/generic.py` line 3577 the option `"multiarrow_align": "t" ...` to `"multiarrow_align": "c" ...`

