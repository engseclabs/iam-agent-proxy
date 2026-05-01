# Experiment: Editing IAM Identity Center Roles

**Date:** 2026-04-29  
**Account:** 278835131762  
**Target role:** `arn:aws:iam::278835131762:role/aws-reserved/sso.amazonaws.com/us-east-2/AWSReservedSSO_SandboxPowerUser_50d858085657c5c1`

## Goal

Modify the trust policy of the SSO-managed role to allow self-assumption, then test restricting permissions via a session policy when assuming it as `sandbox-poweruser`.

## Findings

### IAM Identity Center roles cannot be modified

Attempting to update the trust policy via `sandbox-admin` returned:

```
An error occurred (UnmodifiableEntity) when calling the UpdateAssumeRolePolicy operation:
Cannot perform the operation on the protected role
'AWSReservedSSO_SandboxPowerUser_50d858085657c5c1' - this role is only modifiable by AWS
```

Roles under the `/aws-reserved/` path are fully managed by IAM Identity Center and are protected from direct modification — even by account administrators. AWS enforces this restriction regardless of the caller's IAM permissions.

### Original trust policy (read-only)

The existing trust policy allows assumption only via SAML federation through the SSO SAML provider:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::278835131762:saml-provider/AWSSSO_14261ecc5102c219_DO_NOT_DELETE"
      },
      "Action": [
        "sts:AssumeRoleWithSAML",
        "sts:TagSession"
      ],
      "Condition": {
        "StringEquals": {
          "SAML:aud": "https://signin.aws.amazon.com/saml"
        }
      }
    }
  ]
}
```

## Conclusion

Self-assumption of IAM Identity Center-managed roles is not possible through the IAM API. To test session policy restriction, the approach would be to create a separate, non-reserved IAM role that the SSO role can assume, then pass a restrictive `--policy` to `sts:AssumeRole`. Experiment ended before that step.
