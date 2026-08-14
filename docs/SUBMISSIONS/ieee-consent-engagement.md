# IEEE Consent/Risk Engagement Note (Draft)

> Status: ready for review; intended for IEEE 7012 / 7007-series discussions.

## Positioning

KineGrant is an authorization layer, not a consent ontology. It offers
machine-readable action terms (`kg.action.*`), risk tiers, approval tiers,
physical constraints, and signed receipts that consent and risk ontologies can
reference without adopting a vendor stack.

## Offerings to IEEE work

- action vocabulary with risk and data-sensitivity metadata
  (`spec/ACTION-VOCABULARY.md`);
- MyTerms-style bridge for machine-readable personal privacy terms
  (`src/kinegrant/adapters/ieee7012.py`);
- bounded model checker and static policy analysis for reproducible policy
  reasoning (`src/kinegrant/modelcheck.py`, `src/kinegrant/semantics.py`);
- reproducible evidence: MPT v0.2 and conformance L1-L4.

## Ask

A review slot or joint note to map KineGrant action terms onto IEEE consent
and risk taxonomies.
