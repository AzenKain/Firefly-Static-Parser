use il2cpp_dumper::config::Config;

pub fn static_config() -> Config {
    let mut config = Config::default();
    config.generate_struct = false;
    config.generate_dummy_dll = false;
    config.split_dump_per_type = false;
    config.generate_generics_dump = false;
    config.generate_cpp_scaffold = false;
    config.generate_unity_headers = false;
    config.dump_disassembly = false;
    config.require_any_key = false;
    config
}
