# 📦 Deployment SKUs

The broker SKUs (`dev`, `prod`, and `premium`) deploy the same application and
security controls. The `poc` profile is an intentionally separate,
direct-ingestion experiment.

## `poc` — Proof of Concept

Optimized for a short-lived, resource-constrained pilot.

- no Function App or App Service plan
- no Storage Account
- no App Configuration or Key Vault
- no Application Insights
- no separate Data Collection Endpoint
- 30-day Log Analytics retention
- 1-GB/day ingestion cap
- direct DCR logs-ingestion endpoint
- DCR-scoped RBAC for an existing App Registration

This profile is intentionally not architecture-equivalent to the supported
broker profiles. It moves an Entra workload credential onto each participating
endpoint and removes independent certificate and payload validation. Use it
only for the bounded experiment described in the
[Proof of Concept direct-ingestion plan](poc-direct-ingestion.md).

## `dev`

Optimized for development and a small lab ring.

- Functions Consumption `Y1`
- scale to zero
- maximum 10 instances
- 30-day Log Analytics retention
- 1-GB/day ingestion cap
- Azure App Configuration Free

Cold starts are expected. Do not use this profile for latency baselines where
broker startup time must be negligible.

## `prod`

Production baseline for most tenants.

- Functions Elastic Premium `EP1`
- one warm worker
- maximum 20 instances
- 90-day retention
- 20-GB/day ingestion cap
- Azure App Configuration Standard

This removes Consumption cold-start variability while keeping the architecture
simple and fully managed.

## `premium`

For large or business-critical telemetry populations.

- Functions Elastic Premium `EP2`
- two warm workers
- maximum 50 instances
- zone redundancy where supported
- 365-day retention
- 100-GB/day ingestion cap
- Azure App Configuration Standard

The initial premium profile avoids preview edge mTLS features. A future network
module can add Application Gateway WAF v2 and private endpoints without
changing the broker contract.

## Choosing a profile

| Requirement | Choose |
|---|---|
| Short-lived constrained pilot | `poc` |
| Functional evaluation or CI deployment | `dev` |
| Stable production latency and normal tenant scale | `prod` |
| Higher throughput, longer retention, zone redundancy | `premium` |

Review Azure pricing, regional SKU availability, quota, and privacy
requirements before deployment.
