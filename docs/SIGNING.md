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

`.github/workflows/release.yml` signs both artifacts on a tagged release using
**Azure Trusted Signing**, not a `.pfx`. All five secrets must be set (Settings
→ Secrets and variables → Actions); the signing steps are skipped when
`AZURE_CLIENT_ID` is empty:

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | the Entra tenant holding the signing identity |
| `AZURE_CLIENT_ID` | app registration (service principal) client ID |
| `AZURE_CLIENT_SECRET` | that app registration's client secret |
| `TRUSTED_SIGNING_ENDPOINT` | e.g. `https://eus.codesigning.azure.net` |
| `TRUSTED_SIGNING_ACCOUNT` | Trusted Signing account name |
| `TRUSTED_SIGNING_PROFILE` | certificate profile name within that account |

The service principal needs the **Trusted Signing Certificate Profile Signer**
role on the account.

> Earlier revisions of this page described `SIGN_PFX_BASE64` / `SIGN_PASSWORD`.
> The workflow has never read those. Setting them produces a green release with
> silently unsigned binaries, which is the worst of both outcomes — check the
> `Sign the app exe` step's status in the release run rather than assuming.

**Releases through v0.3.0 are unsigned**, because these secrets are not set on
the repository. Windows SmartScreen will warn on first run. For a security tool
that is a poor default: users learn to click through exactly the warning that
protects them.

## Verify a signature

```powershell
Get-AuthenticodeSignature dist\AetherisQuantumCore.exe | Format-List
signtool verify /pa /v dist\AetherisQuantumCore.exe
```

`Status` should be `Valid` and the timestamp present.
