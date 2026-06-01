use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct InputPaths {
    pub game_assembly: PathBuf,
    pub metadata: PathBuf,
    pub startup_metadata: Option<PathBuf>,
    pub output_dir: PathBuf,
}

impl InputPaths {
    pub fn from_env() -> Self {
        let args: Vec<String> = std::env::args().skip(1).collect();

        let game_assembly = args
            .first()
            .map(PathBuf::from)
            .unwrap_or_else(|| resolve_default_file("GameAssembly.dll"));
        let metadata = args
            .get(1)
            .map(PathBuf::from)
            .unwrap_or_else(|| resolve_default_file("global-metadata.dat"));
        let output_dir = args
            .get(2)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("static-output"));
        let startup_metadata = args
            .get(3)
            .map(PathBuf::from)
            .or_else(|| resolve_startup_metadata(&metadata));

        Self {
            game_assembly,
            metadata,
            startup_metadata,
            output_dir,
        }
    }
}

fn resolve_default_file(name: &str) -> PathBuf {
    let direct = PathBuf::from(name);
    if direct.exists() {
        return direct;
    }

    let parent = Path::new("..").join(name);
    if parent.exists() {
        return parent;
    }

    direct
}

fn resolve_startup_metadata(global_metadata: &Path) -> Option<PathBuf> {
    if let Some(parent) = global_metadata.parent() {
        let sibling = parent.join("startup-metadata.dat");
        if sibling.exists() {
            return Some(sibling);
        }
    }

    let direct = PathBuf::from("startup-metadata.dat");
    if direct.exists() {
        return Some(direct);
    }

    let parent = Path::new("..").join("startup-metadata.dat");
    if parent.exists() {
        return Some(parent);
    }

    None
}
