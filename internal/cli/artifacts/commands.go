package artifacts

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/artifacts"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/asc"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/cli/shared"
	"github.com/rudrankriyam/App-Store-Connect-CLI/internal/rootfs"
)

// IPAInfoCommand prints an offline IPA manifest.
func IPAInfoCommand() *ffcli.Command {
	fs := flag.NewFlagSet("ipa-info", flag.ExitOnError)
	path := fs.String("path", "", "Path to an .ipa")
	includeEntitlements := fs.Bool("include-entitlements", false, "Include the embedded profile entitlements map")
	includeProfile := fs.Bool("include-profile", false, "Include the embedded profile summary")
	verifySignature := fs.Bool("verify-signature", false, "Verify the main executable's code signature and certificate chain offline; exits 1 unless valid")
	output := shared.BindOutputFlags(fs)
	return &ffcli.Command{
		Name:       "ipa-info",
		ShortUsage: "asc ipa-info --path PATH [--include-entitlements] [--include-profile] [--verify-signature]",
		ShortHelp:  "Inspect a local IPA without contacting App Store Connect.",
		LongHelp: `Inspect a local IPA and print bundle identity, signer identity, nested bundles, and optional profile fields.

The command does not upload the artifact or call Apple. An unreadable archive or an IPA without an embedded profile exits 1 after writing a receipt.
Status readable means metadata was parsed. Status unsigned means no embedded profile was found; it is not a code-signature verdict.
codeSignature classifies the main executable's embedded code signature as signed, ad-hoc, unsigned, or unreadable. For a universal binary, the slice stored first is read.
signer describes the leaf certificate in a signed executable's CMS signature and is null otherwise. teamId comes from that certificate, or from the embedded profile when no certificate provides one.
An unreadable code signature prints a warning to stderr and does not change the exit code.

Without --verify-signature, signatures and certificate chains are not verified and signatureVerification is not-verified.
With --verify-signature, the check runs offline, with no network or revocation checks. Trust is anchored at the embedded Apple Root CA and Apple Root CA - G3; the embedded WWDR G3, G5, and G6 and Developer ID intermediates and the certificates in the signature complete the chain. It verifies:
  - the CMS signature over the primary code directory, and that alternate code directories are listed in its signed CDHashes
  - every code directory's page hashes for the Mach-O slice read above, and the hashes of the embedded requirements and entitlements blobs, Info.plist, and _CodeSignature/CodeResources, each of which must be sealed when present
  - that the signer chains to an Apple root at the current time. Signing times in the signature are not trusted, and secure timestamps are not evaluated, so a signature whose certificate has since expired reports expired
It does not verify nested bundles, other slices of a universal binary, the resource files CodeResources lists, the embedded profile, or certificate policy markers. SHA-1 certificate signatures are not accepted.
signatureVerification is then valid, invalid, untrusted-chain (including ad-hoc signatures), expired, or unsupported, and signatureVerificationDetail explains it. Any result other than valid exits 1 after writing the receipt.

Examples:
  asc ipa-info --path ./App.ipa --output json
  asc ipa-info --path ./App.ipa --include-profile --include-entitlements --output json
  asc ipa-info --path ./App.ipa --verify-signature --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			return runArtifactInfo(ctx, args, artifactInfoConfig{
				Kind:                "ipa-info",
				Path:                *path,
				IncludeEntitlements: *includeEntitlements,
				IncludeProfile:      *includeProfile,
				VerifySignature:     *verifySignature,
				Output:              *output.Output,
				Pretty:              *output.Pretty,
			})
		},
	}
}

// PKGInfoCommand prints an offline flat package manifest.
func PKGInfoCommand() *ffcli.Command {
	fs := flag.NewFlagSet("pkg-info", flag.ExitOnError)
	path := fs.String("path", "", "Path to a flat component .pkg")
	verifySignature := fs.Bool("verify-signature", false, "Verify the package signature and certificate chain offline; exits 1 unless valid")
	output := shared.BindOutputFlags(fs)
	return &ffcli.Command{
		Name:       "pkg-info",
		ShortUsage: "asc pkg-info --path PATH [--verify-signature]",
		ShortHelp:  "Inspect a local flat component package without contacting Apple.",
		LongHelp: `Inspect a local flat xar .pkg and print the product identifier, version, install location, component bundle identifiers, and signer identity.

The command does not expand the package onto disk or call Apple. An unreadable package exits 1 after writing a receipt.
Status readable means PackageInfo was parsed. packageSignature is signed, unsigned, or unreadable, based on the certificates in the package's table of contents.
signer describes the first listed signing certificate and is null for an unsigned package. An unsigned package still exits 0.
Signature fields are also reported on an unreadable receipt when the table of contents was read, for example for a signed product archive without PackageInfo.
An unreadable package signature prints a warning to stderr and does not change the exit code.

Without --verify-signature, package signatures and certificate chains are not verified and signatureVerification is not-verified.
With --verify-signature, the check runs offline, with no network or revocation checks. Trust is anchored at the embedded Apple Root CA and Apple Root CA - G3; the embedded WWDR G3, G5, and G6 and Developer ID intermediates and the certificates in the table of contents complete the chain. It verifies:
  - that the checksum stored in the heap matches the compressed table of contents
  - the RSA signature over that checksum
  - that the first listed certificate chains to an Apple root at the current time. The table of contents creation time is not trusted, so a package whose certificate has since expired reports expired
It does not recompute file payload checksums, verify a CMS x-signature, or check certificate policy markers. A package with only an x-signature is unsupported. SHA-1 certificate signatures are not accepted.
signatureVerification is then valid, invalid, untrusted-chain, expired, or unsupported, and signatureVerificationDetail explains it. Any result other than valid exits 1 after writing the receipt.

Examples:
  asc pkg-info --path ./App.pkg --output json
  asc pkg-info --path ./App.pkg --verify-signature --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			return runArtifactInfo(ctx, args, artifactInfoConfig{
				Kind:            "pkg-info",
				Path:            *path,
				VerifySignature: *verifySignature,
				Output:          *output.Output,
				Pretty:          *output.Pretty,
			})
		},
	}
}

type artifactInfoConfig struct {
	Kind                string
	Path                string
	IncludeEntitlements bool
	IncludeProfile      bool
	VerifySignature     bool
	Output              string
	Pretty              bool
}

func runArtifactInfo(ctx context.Context, args []string, config artifactInfoConfig) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) > 0 {
		return shared.UsageErrorf("%s does not accept positional arguments", config.Kind)
	}
	path := strings.TrimSpace(config.Path)
	if path == "" {
		return shared.UsageErrorf("%s: --path is required", config.Kind)
	}
	if _, err := shared.ValidateOutputFormat(config.Output, config.Pretty); err != nil {
		return shared.UsageError(err.Error())
	}
	unreadable := func(err error) error {
		if printErr := shared.PrintOutput(unreadableReceipt(config.Kind, path, config.VerifySignature), config.Output, config.Pretty); printErr != nil {
			return printErr
		}
		return fmt.Errorf("%s: %w", config.Kind, err)
	}
	file, err := rootfs.OpenFile(path)
	if err != nil {
		return unreadable(err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return unreadable(err)
	}
	switch config.Kind {
	case "ipa-info":
		manifest, inspectErr := artifacts.InspectIPAWithOptions(file, info.Size(), artifacts.IPAOptions{
			IncludeEntitlements: config.IncludeEntitlements,
			IncludeProfile:      config.IncludeProfile,
			VerifySignature:     config.VerifySignature,
		})
		receipt := ipaReceipt(path, manifest)
		if printErr := shared.PrintOutput(receipt, config.Output, config.Pretty); printErr != nil {
			return printErr
		}
		if manifest.CodeSignatureError != "" {
			fmt.Fprintf(os.Stderr, "Warning: ipa-info: code signature is unreadable: %s\n", manifest.CodeSignatureError)
		}
		if inspectErr != nil || manifest.Status != "readable" {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("IPA has no embedded profile; code signature was not verified")
			}
			return fmt.Errorf("ipa-info: %w", inspectErr)
		}
		return verificationError(config.Kind, manifest.SignatureVerification)
	case "pkg-info":
		manifest, inspectErr := artifacts.InspectPKGWithOptions(file, info.Size(), artifacts.PKGOptions{VerifySignature: config.VerifySignature})
		receipt := pkgReceipt(path, manifest)
		if printErr := shared.PrintOutput(receipt, config.Output, config.Pretty); printErr != nil {
			return printErr
		}
		if manifest.PackageSignatureError != "" {
			fmt.Fprintf(os.Stderr, "Warning: pkg-info: package signature is unreadable: %s\n", manifest.PackageSignatureError)
		}
		if inspectErr != nil || manifest.Status != "readable" {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("package is unreadable")
			}
			return fmt.Errorf("pkg-info: %w", inspectErr)
		}
		return verificationError(config.Kind, manifest.SignatureVerification)
	default:
		return fmt.Errorf("unknown artifact inspector %q", config.Kind)
	}
}

// verificationError fails a requested verification that did not come back valid.
func verificationError(kind string, verification *artifacts.SignatureVerification) error {
	if verification == nil || verification.Status == artifacts.VerificationValid {
		return nil
	}
	return fmt.Errorf("%s: signature verification %s: %s", kind, verification.Status, verification.Detail)
}

// verificationFields returns the receipt's signatureVerification and detail.
func verificationFields(verification *artifacts.SignatureVerification) (string, string) {
	if verification == nil {
		return "not-verified", ""
	}
	return verification.Status, verification.Detail
}

func ipaReceipt(path string, manifest artifacts.IPAManifest) *asc.ArtifactIPAInfo {
	status, detail := verificationFields(manifest.SignatureVerification)
	info := &asc.ArtifactIPAInfo{
		SignatureVerification:       status,
		SignatureVerificationDetail: detail,
		Path:                        path,
		BundleID:                    manifest.BundleID,
		Name:                        manifest.Name,
		Version:                     manifest.Version,
		BuildNumber:                 manifest.BuildNumber,
		MinimumOSVersion:            manifest.MinimumOSVersion,
		Platforms:                   manifest.Platforms,
		TeamID:                      manifest.TeamID,
		SignerCommonName:            manifest.SignerCommonName,
		Status:                      manifest.Status,
		NestedBundles:               make([]asc.ArtifactNestedBundle, 0, len(manifest.NestedBundles)),
		CodeSignature:               manifest.CodeSignature,
		Signer:                      signerReceipt(manifest.Signer),
	}
	for _, nested := range manifest.NestedBundles {
		info.NestedBundles = append(info.NestedBundles, asc.ArtifactNestedBundle{
			BundleID: nested.BundleID,
			Name:     nested.Name,
			Path:     nested.Path,
		})
	}
	if manifest.Entitlements != nil {
		info.Entitlements = manifest.Entitlements
	}
	if manifest.Profile != nil {
		info.Profile = &asc.ArtifactProfileSummary{
			Name:           manifest.Profile.Name,
			UUID:           manifest.Profile.UUID,
			ExpirationDate: manifest.Profile.ExpirationDate,
			ProfileType:    manifest.Profile.ProfileType,
		}
	}
	return info
}

func pkgReceipt(path string, manifest artifacts.PKGManifest) *asc.ArtifactPKGInfo {
	status, detail := verificationFields(manifest.SignatureVerification)
	return &asc.ArtifactPKGInfo{
		SignatureVerification:       status,
		SignatureVerificationDetail: detail,
		Path:                        path,
		ProductID:                   manifest.ProductID,
		Version:                     manifest.Version,
		InstallLocation:             manifest.InstallLocation,
		BundleIDs:                   manifest.BundleIDs,
		SignerCommonName:            manifest.SignerCommonName,
		TeamID:                      manifest.TeamID,
		Status:                      manifest.Status,
		PackageSignature:            manifest.PackageSignature,
		Signer:                      signerReceipt(manifest.Signer),
	}
}

func signerReceipt(signer *artifacts.SignerIdentity) *asc.ArtifactSigner {
	if signer == nil {
		return nil
	}
	return &asc.ArtifactSigner{
		CommonName:        signer.CommonName,
		TeamID:            signer.TeamID,
		Organization:      signer.Organization,
		IssuerCommonName:  signer.IssuerCommonName,
		SerialNumber:      signer.SerialNumber,
		NotBefore:         signer.NotBefore,
		NotAfter:          signer.NotAfter,
		SHA1Fingerprint:   signer.SHA1Fingerprint,
		SHA256Fingerprint: signer.SHA256Fingerprint,
	}
}

func unreadableReceipt(kind, path string, verify bool) any {
	var verification *artifacts.SignatureVerification
	if verify {
		verification = &artifacts.SignatureVerification{Status: artifacts.VerificationUnsupported, Detail: "artifact could not be read"}
	}
	status, detail := verificationFields(verification)
	if kind == "pkg-info" {
		return &asc.ArtifactPKGInfo{
			SignatureVerification: status, SignatureVerificationDetail: detail, Path: path, Status: "unreadable",
		}
	}
	return &asc.ArtifactIPAInfo{SignatureVerification: status, SignatureVerificationDetail: detail, Path: path, Status: "unreadable"}
}
