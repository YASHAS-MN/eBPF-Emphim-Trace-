# EphimTrace offline forensic frontend

Open `index.html` directly in a modern browser, or serve this directory with any static HTTP server. No Node.js, npm, network connection, or build step is required. `vendor/` contains the pinned browser bundles for Three.js and 3d-force-graph.

The page starts with an embedded composite kill-chain sample. Use **Load DAG JSON** to open an `ephimtrace_dag.json` snapshot, drop a JSON file anywhere on the window, **Load Timeline MD** to show the generated report, or **Reload Snapshot** to re-read `ephimtrace_dag.json` when the browser permits local file fetches (HTTP hosting is recommended for reload). The controls support Force Orbit and chronological forensic strata, entity/edge filters, component isolation, raw metadata inspection, and timeline playback.

All rendering and parsing occurs locally. The frontend accepts the EphimTrace version 1.0 node and edge contract; unknown fields are preserved and displayed by the inspector.
