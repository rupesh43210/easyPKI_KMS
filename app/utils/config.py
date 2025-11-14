"""
Utility functions - Configuration loader
"""
import yaml
from pathlib import Path

def load_config(config_path='config/config.yaml'):
    """Load configuration from YAML file"""
    config_file = Path(config_path)
    
    if not config_file.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")
    
    with open(config_file, 'r') as f:
        config = yaml.safe_load(f)
    
    return config
