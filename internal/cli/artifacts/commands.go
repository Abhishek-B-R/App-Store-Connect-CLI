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
	output := shared.BindOutputFlags(fs)
	return &ffcli.Command{
		Name:       "ipa-info",
		ShortUsage: "asc ipa-info --path PATH [--include-entitlements] [--include-profile]",
		ShortHelp:  "Inspect a local IPA without contacting App Store Connect.",
		LongHelp: `Inspect a local IPA and print bundle identity, signer identity, nested bundles, and optional profile fields.

The command does not upload the artifact or call Apple. An unreadable archive or an IPA without an embedded profile exits 1 after writing a receipt.
Status readable means metadata was parsed. Status unsigned means no embedded profile was found; it is not a code-signature verdict.
codeSignature classifies the main executable's embedded code signature as signed, ad-hoc, unsigned, or unreadable. For a universal binary, the slice stored first is read.
signer describes the leaf certificate in a signed executable's CMS signature and is null otherwise. teamId comes from that certificate, or from the embedded profile when no certificate provides one.
An unreadable code signature prints a warning to stderr and does not change the exit code. Signatures and certificate chains are not verified, and signatureVerification is always not-verified.

Examples:
  asc ipa-info --path ./App.ipa --output json
  asc ipa-info --path ./App.ipa --include-profile --include-entitlements --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			return runArtifactInfo(ctx, args, artifactInfoConfig{
				Kind:                "ipa-info",
				Path:                *path,
				IncludeEntitlements: *includeEntitlements,
				IncludeProfile:      *includeProfile,
				Output:              *output.Output,
				Pretty:              *output.Pretty,
			})
		},
	}
}

// PKGInfoCommand prints an offline flat package or product archive manifest.
func PKGInfoCommand() *ffcli.Command {
	fs := flag.NewFlagSet("pkg-info", flag.ExitOnError)
	path := fs.String("path", "", "Path to a flat component package or product archive .pkg")
	output := shared.BindOutputFlags(fs)
	return &ffcli.Command{
		Name:       "pkg-info",
		ShortUsage: "asc pkg-info --path PATH",
		ShortHelp:  "Inspect a local flat package or product archive without contacting Apple.",
		LongHelp: `Inspect a local flat xar .pkg and print the product identifier, version, install location, component bundle identifiers, and signer identity.

A flat component package is read from its PackageInfo. A product archive, such as productbuild or Xcode writes for the Mac App Store, is read from its Distribution and the PackageInfo of each embedded component package.
For a product archive, productId, version, minimumOSVersion, and hostArchitectures come from the Distribution, and components lists each embedded component package.
The primary component is the one whose pkg-ref matches the product identifier, or else the first embedded one. bundleId, buildNumber, and platforms come from the app Info.plist in its payload, falling back to its PackageInfo.
The app Info.plist is read from a gzip, bzip2, or uncompressed cpio payload in memory, with the same scan and compression-ratio limits as ipa-info. When it cannot be read, or another component is unreadable, a warning is printed to stderr and the exit code is unchanged.

The command does not expand the package onto disk or call Apple. An unreadable package exits 1 after writing a receipt.
Status readable means PackageInfo was parsed, or for a product archive the Distribution and the primary component's PackageInfo. packageSignature is signed, unsigned, or unreadable, based on the certificates in the package's table of contents.
signer describes the first listed signing certificate and is null for an unsigned package. An unsigned package still exits 0.
Signature fields are also reported on an unreadable receipt when the table of contents was read.
An unreadable package signature prints a warning to stderr and does not change the exit code. Package signatures and certificate chains are not verified, and signatureVerification is always not-verified.

Examples:
  asc pkg-info --path ./App.pkg --output json`,
		FlagSet:   fs,
		UsageFunc: shared.DefaultUsageFunc,
		Exec: func(ctx context.Context, args []string) error {
			return runArtifactInfo(ctx, args, artifactInfoConfig{
				Kind:   "pkg-info",
				Path:   *path,
				Output: *output.Output,
				Pretty: *output.Pretty,
			})
		},
	}
}

type artifactInfoConfig struct {
	Kind                string
	Path                string
	IncludeEntitlements bool
	IncludeProfile      bool
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
		if printErr := shared.PrintOutput(unreadableReceipt(config.Kind, path), config.Output, config.Pretty); printErr != nil {
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
		manifest, inspectErr := artifacts.InspectIPA(file, info.Size(), config.IncludeEntitlements, config.IncludeProfile)
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
		return nil
	case "pkg-info":
		manifest, inspectErr := artifacts.InspectPKG(file, info.Size())
		receipt := pkgReceipt(path, manifest)
		if printErr := shared.PrintOutput(receipt, config.Output, config.Pretty); printErr != nil {
			return printErr
		}
		if manifest.PackageSignatureError != "" {
			fmt.Fprintf(os.Stderr, "Warning: pkg-info: package signature is unreadable: %s\n", manifest.PackageSignatureError)
		}
		for _, warning := range manifest.Warnings {
			fmt.Fprintf(os.Stderr, "Warning: pkg-info: %s\n", warning)
		}
		if inspectErr != nil || manifest.Status != "readable" {
			if inspectErr == nil {
				inspectErr = fmt.Errorf("package is unreadable")
			}
			return fmt.Errorf("pkg-info: %w", inspectErr)
		}
		return nil
	default:
		return fmt.Errorf("unknown artifact inspector %q", config.Kind)
	}
}

func ipaReceipt(path string, manifest artifacts.IPAManifest) *asc.ArtifactIPAInfo {
	info := &asc.ArtifactIPAInfo{
		SignatureVerification: "not-verified",
		Path:                  path,
		BundleID:              manifest.BundleID,
		Name:                  manifest.Name,
		Version:               manifest.Version,
		BuildNumber:           manifest.BuildNumber,
		MinimumOSVersion:      manifest.MinimumOSVersion,
		Platforms:             manifest.Platforms,
		TeamID:                manifest.TeamID,
		SignerCommonName:      manifest.SignerCommonName,
		Status:                manifest.Status,
		NestedBundles:         make([]asc.ArtifactNestedBundle, 0, len(manifest.NestedBundles)),
		CodeSignature:         manifest.CodeSignature,
		Signer:                signerReceipt(manifest.Signer),
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
	info := &asc.ArtifactPKGInfo{
		SignatureVerification: "not-verified",
		Path:                  path,
		ProductID:             manifest.ProductID,
		Version:               manifest.Version,
		InstallLocation:       manifest.InstallLocation,
		BundleIDs:             manifest.BundleIDs,
		BundleID:              manifest.BundleID,
		BuildNumber:           manifest.BuildNumber,
		MinimumOSVersion:      manifest.MinimumOSVersion,
		Platforms:             manifest.Platforms,
		HostArchitectures:     manifest.HostArchitectures,
		SignerCommonName:      manifest.SignerCommonName,
		TeamID:                manifest.TeamID,
		Status:                manifest.Status,
		PackageSignature:      manifest.PackageSignature,
		Signer:                signerReceipt(manifest.Signer),
	}
	for _, component := range manifest.Components {
		receipt := asc.ArtifactPKGComponent{
			Path:            component.Path,
			Identifier:      component.Identifier,
			Version:         component.Version,
			InstallLocation: component.InstallLocation,
			InstallKBytes:   component.InstallKBytes,
			BundleIDs:       component.BundleIDs,
			Primary:         component.Primary,
		}
		if app := component.App; app != nil {
			receipt.App = &asc.ArtifactPKGComponentApp{
				Path:             app.Path,
				BundleID:         app.BundleID,
				Name:             app.Name,
				Version:          app.Version,
				BuildNumber:      app.BuildNumber,
				MinimumOSVersion: app.MinimumOSVersion,
				Platforms:        app.Platforms,
			}
		}
		info.Components = append(info.Components, receipt)
	}
	return info
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

func unreadableReceipt(kind, path string) any {
	if kind == "pkg-info" {
		return &asc.ArtifactPKGInfo{
			SignatureVerification: "not-verified", Path: path, Status: "unreadable",
		}
	}
	return &asc.ArtifactIPAInfo{SignatureVerification: "not-verified", Path: path, Status: "unreadable"}
}
