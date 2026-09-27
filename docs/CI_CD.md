# CI/CD Integrations

## GitHub Actions

Install `asc` using the official setup action:

```yaml
- uses: rudrankriyam/setup-asc@v1
  with:
    version: latest

- run: asc --help
```

For end-to-end examples, see:
https://github.com/rudrankriyam/setup-asc

## GitLab CI/CD Components

Use the official `asc-ci-components` repository:

```yaml
include:
  - component: gitlab.com/rudrankriyam/asc-ci-components/run@main
    inputs:
      stage: deploy
      job_prefix: release
      asc_version: latest
      command: asc --help
```

For install/run templates and self-managed examples:
https://github.com/rudrankriyam/asc-ci-components

## Bitrise

Use the official `setup-asc` Bitrise step repository:

```yaml
workflows:
  primary:
    steps:
    - git::https://github.com/rudrankriyam/steps-setup-asc.git@main:
        inputs:
        - mode: run
        - version: latest
        - command: asc --help
```

## CircleCI

Use the official CircleCI orb repository:
https://github.com/rudrankriyam/asc-orb

## Code signing on a fresh runner

A fresh macOS runner can go from an App Store Connect API key to a signed
archive without hand-written `security` calls. Provide `ASC_KEY_ID`,
`ASC_ISSUER_ID`, and `ASC_PRIVATE_KEY_B64` from the CI secret store, then run
these commands in one shell step:

1. First run only, when the team has no active certificate of the required
   type: `asc signing fetch --create-missing --create-missing-certificate`
   creates the private key, CSR, certificate, profile, and a
   password-protected `.p12`. Push that identity to the encrypted store
   (`asc signing sync push` with `--identity`) before building, because the
   private key exists only on this runner.
2. Every later run: `asc signing sync pull` decrypts the stored identity and
   profiles.
3. `asc signing keychain install --confirm` imports the identity into a new
   dedicated keychain, and `asc profiles local install` installs each profile.
4. `asc xcode signing plan` with `--profile` infers each target's signing
   settings and an `ExportOptions.plist` from the profiles, and
   `asc xcode signing apply --confirm` writes those settings into the project.
5. `asc xcode archive`, then `asc xcode export` with `--export-options`,
   produce the signed archive and IPA.
6. `asc signing keychain delete --confirm` removes the job keychain.

The first-run commands look like this. The full script, including the
password files, cleanup trap, and later-run variant, is in the
[code signing guide](../guides/code-signing.mdx) and the
[signing command reference](../commands/signing.mdx).

```bash
asc signing fetch --bundle-id com.example.app --profile-type IOS_APP_STORE --create-missing --create-missing-certificate --identity-password-file "$p12_password_file" --output .asc/signing/bootstrap --format json > .asc/signing/fetch-result.json
asc signing sync push --bundle-id com.example.app --profile-type IOS_APP_STORE --repo git@github.com:team/signing.git --password-file "$sync_password_file" --identity "$p12_path" --identity-password-file "$p12_password_file" --output json
asc signing keychain install --identity "$p12_path" --identity-password-file "$p12_password_file" --keychain "$keychain_path" --keychain-password-file "$keychain_password_file" --add-to-search-list --confirm --output json
asc profiles local install --path "$profile_path" --output json
asc xcode signing plan --project Example.xcodeproj --profile "$profile_path" --configuration Release --export-options-out .asc/artifacts/ExportOptions.plist --output json
asc xcode signing apply --plan .asc/xcode/signing/plan.json --confirm --output json
asc xcode archive --project Example.xcodeproj --scheme Example --configuration Release --archive-path .asc/artifacts/Example.xcarchive
asc xcode export --archive-path .asc/artifacts/Example.xcarchive --export-options .asc/artifacts/ExportOptions.plist --ipa-path .asc/artifacts/Example.ipa
asc signing keychain delete --keychain "$keychain_path" --confirm
```

`p12_path` and `profile_path` come from the `p12Path` and `profileFile` fields
of the fetch receipt. `xcode signing plan` exits 0 with `ready: false` when a
target has no matching profile; check `ready` before applying.

Expired or invalid profiles can already be removed with
`asc signing fetch --delete-stale-profiles`, and certificates can be
deactivated or revoked with `asc certificates`. With Git storage,
`asc signing sync push --renew-expired` replaces an expired synced profile,
`--force-for-new-devices` (optionally with `--include-mac-in-profiles`)
recreates a development or ad hoc profile when its devices change, and
`asc signing sync nuke` removes one profile type with its certificates and
encrypted files. Not available yet: an object-storage backend for
`signing sync`, which is planned.
