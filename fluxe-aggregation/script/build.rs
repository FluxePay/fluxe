//! Build script to compile the SP1 guest program
//!
//! This requires the SP1 toolchain to be installed. Install with:
//! ```
//! curl -L https://sp1.succinct.xyz | bash
//! sp1up
//! ```

use std::process::Command;

fn main() {
    // Check if SP1 toolchain is available
    let rustup_check = Command::new("rustup")
        .args(["run", "succinct", "rustc", "--version"])
        .output();

    match rustup_check {
        Ok(output) if output.status.success() => {
            // SP1 toolchain is available, build the program
            use sp1_build::{build_program_with_args, BuildArgs};

            build_program_with_args(
                "../program",
                BuildArgs {
                    output_directory: Some("../elf".into()),
                    ..Default::default()
                },
            );
        }
        _ => {
            // SP1 toolchain not available, skip building
            println!("cargo:warning=SP1 toolchain 'succinct' not installed. Skipping guest program build.");
            println!("cargo:warning=Install SP1 with: curl -L https://sp1.succinct.xyz | bash && sp1up");

            // Create a placeholder ELF so the main.rs can still compile
            // (though it won't work at runtime without the real ELF)
            let elf_dir = std::path::Path::new("../elf");
            if !elf_dir.exists() {
                std::fs::create_dir_all(elf_dir).ok();
            }

            // Write a placeholder (empty ELF, will fail at runtime)
            let elf_path = elf_dir.join("riscv32im-succinct-zkvm-elf");
            if !elf_path.exists() {
                std::fs::write(&elf_path, b"PLACEHOLDER - SP1 not installed").ok();
            }

            // Set the SP1_ELF env var for include_elf! macro
            println!("cargo:rustc-env=SP1_ELF_fluxe-aggregation-program={}", elf_path.display());
        }
    }
}
