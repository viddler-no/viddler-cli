use std::path::PathBuf;

// Feels like this might not be the most
// robust abstraction, but.. some helpful things
// like solidifying where paths are.
// Less noise and decent names in code
// Could limit to wp
#[derive(Debug)]
pub struct ProjectItemPaths {
    pub from_project: ProjectPath,
    pub full_path: ProjectPath,
    pub server_path: ProjectPath,
}
impl ProjectItemPaths {
    pub fn new(from_project: PathBuf, full_path: PathBuf, server_path: PathBuf) -> Self {
        ProjectItemPaths {
            from_project: ProjectPath::new(from_project),
            full_path: ProjectPath::new(full_path),
            server_path: ProjectPath::new(server_path),
        }
    }
}

// Attempt at convenience :)
#[derive(Debug)]
pub struct ProjectPath(pub PathBuf);
impl ProjectPath {
    pub fn new(path_buf: PathBuf) -> Self {
        ProjectPath(path_buf)
    }
    pub fn buf(&self) -> PathBuf {
        self.0.clone()
    }
    pub fn string(&self) -> String {
        self.0.to_string_lossy().to_string()
    }
    pub fn cow(&self) -> std::borrow::Cow<'_, str> {
        self.0.to_string_lossy()
    }
}
