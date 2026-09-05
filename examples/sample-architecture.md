# Synthetic document-analysis service

A public client submits a document over HTTPS to an API gateway. The gateway authenticates the user with OIDC and sends the document to an application service. The service stores the document in a tenant-partitioned object store and places a job on a queue. A worker retrieves the document, sends approved excerpts to an external LLM provider, and stores the generated summary. The client later retrieves the summary.

The diagram does not specify whether tenant authorization is re-validated by the worker or enforced by the object store. This is intentionally synthetic and contains no real organization or customer information.
