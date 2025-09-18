use std::fmt;

/// Errors that can occur in Merkle tree operations
#[derive(Debug, Clone)]
pub enum TreeError {
    /// Leaf not found in tree
    LeafNotFound,
    
    /// Tree is full
    TreeFull,
    
    /// Invalid index
    InvalidIndex,
    
    /// Invalid depth
    InvalidDepth,
    
    /// Duplicate entry
    DuplicateEntry,
    
    /// Tree corruption detected
    Corrupted,
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TreeError::LeafNotFound => write!(f, "Leaf not found in tree"),
            TreeError::TreeFull => write!(f, "Tree is full"),
            TreeError::InvalidIndex => write!(f, "Invalid index"),
            TreeError::InvalidDepth => write!(f, "Invalid depth"),
            TreeError::DuplicateEntry => write!(f, "Duplicate entry"),
            TreeError::Corrupted => write!(f, "Tree corruption detected"),
        }
    }
}

impl std::error::Error for TreeError {}