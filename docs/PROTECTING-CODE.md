# Protecting your code

Short version: a **public** repo means anyone can read the source. To protect it,
make the source **private** and distribute only the compiled `.exe`. There's a
license (`LICENSE`) that legally forbids copying, reselling, and reverse
engineering.

> Honest limit: no distributed program is 100% theft-proof — a determined person
> can reverse-engineer any `.exe`. The goal here is to (a) stop casual copying of
> your source, and (b) have legal protection. That covers the vast majority of
> real-world "stealing."

## Option A — Private source + public releases repo (recommended)

Keeps your source private **and** keeps auto-update working. Your private repo's
CI builds the exe and publishes it to a small **public** repo that contains only
release binaries (no source).

1. **Make the source repo private:**
   `github.com/Dray973/Aetheris` -> Settings -> General -> Danger Zone ->
   *Change repository visibility* -> **Private**.

2. **Create the public releases repo** (empty, no source):
   New repo -> name it e.g. `Aetheris-app` -> **Public** -> Create.

3. **Create a token** so the private CI can publish to the public repo:
   Settings (your account) -> Developer settings -> **Fine-grained tokens** ->
   Generate new token -> Repository access: *only* `Aetheris-app` ->
   Permissions: **Contents: Read and write** -> Generate. Copy it.

4. **Add the token + repo name to the PRIVATE repo:**
   `Aetheris` -> Settings -> Secrets and variables -> Actions ->
   - **Secrets** tab: New secret `RELEASES_TOKEN` = the token from step 3.
   - **Variables** tab: New variable `RELEASES_REPO` = `Dray973/Aetheris-app`.

   (`release.yml` already reads these — when set, it publishes binaries to the
   public repo; when unset, it publishes to the current repo as before.)

5. **Point the updater at the public repo:** in `aetheris/core/settings.py`
   change the default `update_url` to `github:Dray973/Aetheris-app`, then rebuild
   (`build_all.ps1`) and cut a new release.

Result: source is private; anyone can still download the exe from
`github.com/Dray973/Aetheris-app/releases/latest`; clients auto-update as before.

## Option B — Private repo, host binaries yourself

Make the repo private and host `AetherisQuantumCore.exe` + `version.json` on any
public URL (your own web host / CDN). Set `update_url` to that `version.json`
URL. More flexible, but you manage the hosting.

## Make the exe harder to unpack (optional)

A PyInstaller exe can be unpacked back to Python bytecode. To raise the bar you
can obfuscate before freezing with a tool like **PyArmor**
(https://pyarmor.dev/) and point PyInstaller at the obfuscated output. This is
optional and not foolproof, but deters casual inspection.

## What NOT to do

- **Don't** bake a GitHub token into the app to read a private repo — it's
  extractable from the exe. Use the public-releases-repo pattern instead.
- **Don't** rely on a private repo alone for updates — the updater needs public
  access to check versions.
