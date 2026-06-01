# Firefly Static Parser

Offline static metadata parser for custom IL2CPP-derived static assemblies. Generates C# type definitions (`dump.cs`) and method address maps (`methods.json`) dynamically from binary structures.

## Disclaimer

> [!WARNING]
> **This repository is for educational, academic research, and reverse-engineering study purposes only.**
> - The code is provided "as-is" without any express or implied warranty.
> - The developers have no affiliation with, and do not represent, any game developer, publisher, or third-party company.
> - Using this tool on proprietary or copyrighted game files might violate local laws or end-user license agreements (EULAs). Use at your own risk.

## Features

- **Decryption**: Decodes obfuscated metadata strings, method layouts, and generic type instantiations.
- **Dynamic Address Discovery**: Dynamically resolves metadata registrations, descriptor layouts, and attribute XOR keys directly from the PE headers.
- **Watermarking**: Prepend signatures on output files to confirm static parsing origin.
- **Clean output**: Produces standard C# type representations (`dump.cs`) and JSON formatted method maps (`methods.json`).

## Inputs

The parser requires local copies of:
- `GameAssembly.dll`
- `global-metadata.dat`
- `startup-metadata.dat` (required for image/type range mapping)

## Building

Build the release binary using Cargo:

```bash
cargo build --release --bin firefly-static-parser
```

The compiled binary will be placed at `target/release/firefly-static-parser.exe`.

## Usage

### Default Behavior

If run without arguments, the parser searches the current directory or its parent for the input files and writes outputs to the `static-output` directory:

```bash
./firefly-static-parser.exe
```

### Custom Paths

You can manually specify inputs and output directories:

```bash
./firefly-static-parser.exe <path_to_GameAssembly.dll> <path_to_global-metadata.dat> <path_to_output_dir> <path_to_startup-metadata.dat>
```

Example:
```bash
./firefly-static-parser.exe GameAssembly.dll global-metadata.dat my-dump-folder startup-metadata.dat
```
