# Public development fixtures

- `runtime.hdr`: public SE header from IBM s390-tools' test asset
  `rust/pv/tests/assets/exp/secure_guest.hdr`, source commit
  `b1d612b4a6a84440e16aae6d66e5f8f4be4e977f`.
- `host.crt`: disposable public development HKD created for the isolated
  s390-tools interoperability tests. It is used only with explicit simulation.

There are no private keys, real secret values, production trust anchors or native
hardware claims in these fixtures. Tests generate outer-encryption certificates
and account/wrapping private keys afresh in memory.
