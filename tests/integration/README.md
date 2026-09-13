# tests/integration/

End-to-end tests covering launch -> session -> teardown across crate
boundaries (as opposed to `tests/unit/<domain>/`, which mirrors a single
crate). Not yet populated -- Phase 0 scaffolding only. The first real
integration coverage lands with Phase 3 (VM launch), and Phase 7's exit
gate requires a full multi-prompt end-to-end run here.
