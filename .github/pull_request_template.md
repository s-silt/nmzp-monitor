## Summary

## Why

## Type of change

- [ ] Bug fix
- [ ] Security rule or policy behavior
- [ ] Host adapter
- [ ] Privacy-preserving rewrite
- [ ] Audit export, redaction, or policy-proposal import
- [ ] Documentation
- [ ] Other

## Security impact

Describe what changes for block, rewrite, or audit. Write "none" if the tool-execution boundary is unchanged.

## Testing

Commands actually run, and the result:

```text
npm test
npm run typecheck
npm run build
```

## Checklist

- [ ] tests pass
- [ ] typecheck passes
- [ ] build passes
- [ ] security behavior documented
- [ ] no unnecessary sensitive data logging
- [ ] documentation updated where necessary
- [ ] no tokens, join bundles, real audit exports, or unsanitized logs are attached

For security rules, host adapters, privacy-preserving rewrite, or audit: the pull request includes a test that covers the changed behavior. See CONTRIBUTING.md.

Do not describe this change as an OpenAI partnership, approval, or certification.
