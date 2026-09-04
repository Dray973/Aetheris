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
**Azure Artifact Signing**, not a `.pfx`.

> The service has been renamed twice: Azure Code Signing → Trusted Signing →
> **Artifact Signing**. In the portal, search for **"Artifact Signing
> Accounts"** — searching "Trusted Signing" finds nothing useful. The
> underlying resource type is unchanged
> (`Microsoft.CodeSigning/codesigningaccounts`), and the GitHub action moved to
> `Azure/artifact-signing-action` accordingly.

All six secrets must be set (Settings → Secrets and variables → Actions); the
signing steps are skipped when `AZURE_CLIENT_ID` is empty:

| Secret | Value |
|---|---|
| `AZURE_TENANT_ID` | the Entra tenant holding the signing identity |
| `AZURE_CLIENT_ID` | app registration (service principal) client ID |
| `AZURE_CLIENT_SECRET` | that app registration's client secret |
| `TRUSTED_SIGNING_ENDPOINT` | e.g. `https://eus.codesigning.azure.net` |
| `TRUSTED_SIGNING_ACCOUNT` | Trusted Signing account name |
| `TRUSTED_SIGNING_PROFILE` | certificate profile name within that account |

The service principal needs the **Trusted Signing Certificate Profile Signer**
role on the signing account (the role kept its old name through the rebrand).

Order matters, and the first step is the slow one:

1. Create an **Artifact Signing Account** (regions are limited: East US,
   West US 3, West Central US, North Europe, West Europe).
2. Complete **Identity validation** — Individual or Organisation. Microsoft
   reviews this manually and it takes days. Nothing below is possible until it
   reads *Completed*.
3. Create a **Certificate profile** of type Public Trust. This blade is only
   usable after step 2.
4. Register an app in Entra ID and generate a client secret.
5. Grant that app the signer role on the account (step above).

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
