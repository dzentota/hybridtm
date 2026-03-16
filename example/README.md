# Example: E-Commerce Platform

A complete, runnable HybridTM example modelling a cloud-native PHP e-commerce platform.

## Architecture

```
[Browser] ──HTTPS──► [Web App (Symfony BFF)] ──HTTPS──► [Auth Service]
                              │                                │
                              │ HTTPS                         │ JDBC / Redis
                              ▼                               ▼
                      [Order Service] ◄──── [PostgreSQL] ◄─── │
                              │             [Redis Cache]
                              │ JMS
                              ▼
                      [RabbitMQ] ──► [Order Consumer] ──► [Notification Service]
                                          │
                                          └──JDBC──► [PostgreSQL]

[Web App] ──HTTPS──► [Stripe (external)]
```

### Trust Boundaries

| Zone | Assets |
|------|--------|
| Public Internet | Browser, Stripe |
| DMZ (WAF + Load Balancer) | Web Application |
| Internal VPC | Auth Service, Order Service, Notification Service |
| Data Layer | PostgreSQL, Redis, RabbitMQ |

### Data Assets

| ID | Description | Sensitivity |
|----|-------------|-------------|
| `customer-pii` | Name, email, address (GDPR) | Confidential |
| `user-credentials` | Bcrypt-hashed passwords | Strictly Confidential |
| `session-token` | RS256 JWT | Strictly Confidential |
| `order-data` | Cart, orders, history | Internal |
| `payment-confirmation` | Stripe payment intent result (no PAN) | Restricted |
| `notification-payload` | Transactional email content | Internal |

## Source Files

```
example/
├── threat-model.php                        ← Infrastructure DSL (assets, boundaries)
└── src/
    ├── Controller/
    │   ├── UserController.php              ← register, login, profile, GDPR delete
    │   └── CheckoutController.php          ← cart validation, payment, order placement
    ├── Service/
    │   ├── AuthenticationService.php       ← JWT issue, validate, revoke
    │   └── OrderService.php               ← order creation, status transitions
    ├── Repository/
    │   ├── UserRepository.php             ← user CRUD against PostgreSQL
    │   └── OrderRepository.php            ← order CRUD against PostgreSQL
    └── Consumer/
        └── OrderProcessedConsumer.php     ← async RabbitMQ worker
```

## Running the Example

```bash
# From the repository root:

# 1. Compile DSL + code attributes → Threagile YAML
php bin/hybridtm compile \
    --infra=example/threat-model.php \
    --source=example/src/ \
    --out=build/threagile.yaml

# 2. Generate DFD, risk report, and risk tracking spreadsheet
mkdir -p build/threagile-output
docker run --rm \
    -v "$(pwd)/build:/work" \
    threagile/threagile:latest \
    --model /work/threagile.yaml \
    --output /work/threagile-output

# 3. Open the reports
open build/threagile-output/report.pdf
open build/threagile-output/data-flow-diagram.pdf
```

## What This Example Demonstrates

- **Multi-service modelling** — 9 technical assets across 4 trust boundaries.
- **Multiple `#[AssetId]` contexts** — `web-app`, `auth-service`, and `order-service` each have multiple annotated classes.
- **Repeatable `#[DataFlow]`** — a single method can fan out to multiple targets.
- **`#[Mitigation]`** — CWE-tagged security controls documented inline (CWE-89, CWE-307, CWE-312, CWE-362, CWE-613, …).
- **Async workers** — `OrderProcessedConsumer` shows how queue consumers are modelled.
- **Read-only flows** — `readonly: true` on SELECT-only database calls.
- **Outbox pattern** — DB commit and message publish represented as separate `#[DataFlow]` calls.
- **GDPR flows** — `deleteAccount` and `UserRepository::delete` show how erasure is modelled.
