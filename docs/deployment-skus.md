# 📦 Deployment SKUs

The SKU is an operational profile, not a fork. All profiles deploy the same
application and security controls.

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
| Functional evaluation or CI deployment | `dev` |
| Stable production latency and normal tenant scale | `prod` |
| Higher throughput, longer retention, zone redundancy | `premium` |

Review Azure pricing, regional SKU availability, quota, and privacy
requirements before deployment.
