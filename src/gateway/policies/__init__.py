"""Versioned default policies (OPA pivot).

``v1/`` holds the frozen Rego: the decision library
(``gateway.authz``) plus the default policies for the four preset
families and the PAA10-derived controls, each with an ``opa test``
suite. ``defaults.py`` is the Python-side canonical default rule
content used by ``seed_defaults``; the Rego files are the versioned,
immutable specification, and ``tests/test_rego.py`` enforces
decision-equivalence between the two on representative inputs.
"""

from .defaults import PAA10_RULES, seed_defaults

__all__ = ["PAA10_RULES", "seed_defaults"]
