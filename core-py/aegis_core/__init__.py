"""
aegis-core: AEGIS Governance Enforcement Engine

Python reference implementation of the AEGIS Governance Protocol (AGP-1).
This package provides the core governance runtime that evaluates AI system
actions against registered policies, computes risk scores, and produces
governance decisions.

Modules:
    gateway    — AGP-1 message gateway (ACTION_PROPOSE -> DECISION_RESPONSE)
    capability — Capability declaration and permission registry
    policy     — Policy evaluation engine
    risk       — Risk scoring engine
    audit      — Immutable audit logging
"""

__version__ = "0.1.0"
