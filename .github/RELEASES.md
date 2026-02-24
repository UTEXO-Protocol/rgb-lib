# Release & Bindings Overview

## Architecture

```
rgb-lib (Rust core)
  ├── release.yml (tag v*)
  │   triggers all binding repos via repository_dispatch:
  │
  ├── rgb-lib-go          (uniffi → Go)
  ├── rgb-lib-nodejs      (c-ffi + SWIG → Node.js → npm)
  ├── rgb-lib-c-sharp     (c-ffi → C# → NuGet)
  ├── rgb-lib-python      (uniffi → Python)
  ├── rgb-lib-kotlin      (uniffi → Android/Kotlin)
  ├── rgb-lib-swift       (uniffi → iOS/macOS Swift)
  └── rgb-sdk-rn          (React Native SDK → npm)
```

Each binding repo has its own `release.yml` with two triggers:
- **repository_dispatch** — auto-triggered when rgb-lib creates a release
- **workflow_dispatch** — manual trigger from GitHub Actions UI

## Branches

- `master` — clean fork of upstream [RGB-Tools/rgb-lib](https://github.com/RGB-Tools/rgb-lib), used for syncing
- `utexo-master` — our working branch, all CI/CD runs from here

## When to Create a Release in rgb-lib

Create a release (tag `v*`) when you want to **trigger all bindings at once**. This will:

1. Build uniffi libraries (Linux x64, macOS ARM64)
2. Build c-ffi libraries (Linux x64, macOS ARM64, Windows x64)
3. Create GitHub Release with artifacts
4. Trigger all binding repos to build and publish

If you only need to rebuild a single binding — run its workflow manually instead.

## How to Create a Release

### Option A: Tag push (automatic)
```bash
git tag v0.3.0-beta.10
git push origin v0.3.0-beta.10
```

### Option B: Manual (Actions UI)
Actions → Release → Run workflow → enter version (e.g. `v0.3.0-beta.10`)

## When to Rebuild

### Rebuild ALL bindings (create rgb-lib release)
- Rust core (`src/`) changed — new features, bug fixes, API changes
- C-FFI or uniffi bindings code changed (`bindings/c-ffi/`, `bindings/uniffi/`)
- Dependencies updated (`Cargo.toml`, `Cargo.lock`)

### Rebuild SINGLE binding (manual trigger in that repo)
- Wrapper/glue code changed (e.g. `wrapper.js` in nodejs, `RgbLibWallet.cs` in c-sharp)
- Build configuration changed (CI workflow, package metadata)
- Publishing fix needed (failed npm/NuGet/PyPI publish)

### No rebuild needed
- Documentation changes (README, comments)
- Test-only changes in a binding repo
- CI workflow changes that don't affect the build output

## Binding Repos

| Repo | Binding Type | Publishes To | Platforms |
|------|-------------|-------------|-----------|
| rgb-lib-go | uniffi | GitHub Release | Linux x64, macOS ARM64 |
| rgb-lib-nodejs | c-ffi + SWIG | npm `@utexo/rgb-lib` | Linux x64/ARM64, macOS ARM64 |
| rgb-lib-c-sharp | c-ffi | NuGet `RgbLib` | Linux x64, macOS ARM64, Windows x64 |
| rgb-lib-python | uniffi | PyPI | Linux x64, macOS ARM64 |
| rgb-lib-kotlin | uniffi | GitHub Release (AAR) | Android ARM64, x86_64 |
| rgb-lib-swift | uniffi | GitHub Release (XCFramework) | iOS, iOS Simulator, macOS |
| rgb-sdk-rn | — | npm `@utexo/rgb-sdk-rn` | iOS, Android |

## Required Secrets in rgb-lib

| Secret | Purpose |
|--------|---------|
| `RGB_LIB_GO_PAT` | Trigger rgb-lib-go |
| `RGB_LIB_NODEJS_PAT` | Trigger rgb-lib-nodejs |
| `RGB_LIB_CSHARP_PAT` | Trigger rgb-lib-c-sharp |
| `RGB_LIB_PYTHON_PAT` | Trigger rgb-lib-python |
| `RGB_LIB_KOTLIN_PAT` | Trigger rgb-lib-kotlin |
| `RGB_LIB_SWIFT_PAT` | Trigger rgb-lib-swift |
| `RGB_SDK_RN_PAT` | Trigger rgb-sdk-rn |

Each PAT is a fine-grained GitHub token with Actions + Contents write access to the target repo.
