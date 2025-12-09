import json
import os

# Define project root as the parent directory of this script's location
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CONFIG_PATH = os.path.join(PROJECT_ROOT, 'config.json')

def load_config():
    """Loads the configuration from config.json in the project root."""
    if not os.path.exists(CONFIG_PATH):
        # If config doesn't exist, let's create a default one from the example
        example_config_path = os.path.join(PROJECT_ROOT, 'config-example.json')
        if os.path.exists(example_config_path):
            with open(example_config_path, 'r') as f:
                return json.load(f)
        return {}
    with open(CONFIG_PATH, 'r') as f:
        return json.load(f)

def save_config(config_data):
    """Saves the configuration to config.json in the project root."""
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config_data, f, indent=4)
