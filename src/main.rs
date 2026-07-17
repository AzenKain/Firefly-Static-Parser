mod app;
mod args;
mod config;
mod il2cpp_pe;
mod layout_model;

mod metadata;
mod obfuscated;
mod output;
mod pe_image;
mod static_layout;

fn main() -> anyhow::Result<()> {
    app::run()
}
