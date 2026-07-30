import os


def safe_read_file(base_dir, filename):
    filepath = os.path.join(base_dir, filename)
    with open(filepath, "r") as f:
        return f.read()
