# REST Error Envelope

All Agent FirewallKit REST API errors follow a consistent JSON envelope:

```json
{
  "error": {
    "code": "MACHINE_READABLE_CODE",
    "message": "Human-readable description",
    "reason_code": "OPTIONAL_REASON_CODE",
    "request_id": "uuid-from-x-request-id"
  }
}
```

## Status Code Mapping

| Scenario | HTTP Status | Error Code |
|----------|------------|------------|
| Missing/invalid credentials | 401 | `AUTH_INVALID_CREDENTIALS` |
| Insufficient permissions | 403 | `PERMISSION_DENIED` |
| Resource not found | 404 | `NOT_FOUND` |
| Validation failure | 400 | `INVALID_ARGUMENT` |
| State conflict (e.g., idempotency replay in-progress) | 409 | `CONFLICT` |
| Precondition failed (e.g., wrong resource state) | 412 | `FAILED_PRECONDITION` |
| Rate limit exceeded | 429 | `RATE_LIMITED` |
| Internal error | 500 | `INTERNAL_ERROR` |
| Dependency unavailable | 503 | `UNAVAILABLE` |

## Request ID Propagation

Every response includes the `X-Request-Id` header. If the client sends this header, the server echoes it; otherwise the server generates one.

## gRPC Equivalence

REST error codes map to gRPC status codes as documented in the Protobuf contracts. The `reason_code` field carries the same domain-specific code in both transports.
