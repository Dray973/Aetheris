# Code signing

Authenticode-signing the executable and installer removes the "Unknown
publisher" SmartScreen warning and lets users verify the binaries are from you
and untampered. Signing is **optional** — every build script and the release
workflow produce working (unsigned) binaries when no certificate is configured,
and sign only when one is provided.

## Get a certificate

- **OV (Organization Validation)** code-signing certificate — cheapest; still
  triggers SmartScreen reputation until the binary builds trust.
- **EV (Extended Validation)** certificate — clears SmartScreen immediately;
  usually ships on a hardware token/HSM.

Export an OV certificate to a password-protected `.pfx` for the automated flows
below. (EV tokens can't be exported; sign on the machine with the token
attached, or use a cloud HSM signing service.)

## Sign locally

`installer\build_exe.ps1` signs the one-file exe after building it:

```powershell
# with a .pfx file
powershell -ExecutionPolicy Bypass -File installer\build_exe.ps1 `
    -PfxPath C:\path\to\cert.pfx -PfxPassword 'your-password'

# or a certificate already in your store, by thumbprint
powershell -ExecutionPolicy Bypass -File installer\build_exe.ps1 `
    -Thumbprint AB12CD34...
```

It finds `signtool.exe` (from the Windows SDK), signs with SHA-256, and
**timestamps** the signature (so it stays valid after the cert expires). Without
`-PfxPath`/`-Thumbprint` it just prints `(unsigned)` and continues.

To sign the Inno Setup installer too, sign `installer\Output\AetherisSetup.exe`
with the same `signtool sign` command after compiling it.

## Sign in CI

`.github/workflows/release.yml` signs both artifacts on a tagged release when two
repository secrets are set (Settings → Secrets and variables → Actions):

| Secret | Value |
|---|---|
| `SIGN_PFX_BASE64` | your `.pfx`, base64-encoded (`[Convert]::ToBase64String([IO.File]::ReadAllBytes('cert.pfx'))`) |
| `SIGN_PASSWORD`   | the `.pfx` password |

If `SIGN_PFX_BASE64` is empty the signing step is skipped and unsigned binaries
are published — so the pipeline works before you have a certificate.

## Verify a signature

```powershell
Get-AuthenticodeSignature dist\AetherisQuantumCore.exe | Format-List
signtool verify /pa /v dist\AetherisQuantumCore.exe
```

`Status` should be `Valid` and the timestamp present.
