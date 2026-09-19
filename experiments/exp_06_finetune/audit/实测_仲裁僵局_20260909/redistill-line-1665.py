import os
import json

class ConfigLoader:
    def __init__(self):
        self._cache = {}
        self._loaded_files = []

    def load_config(self, filepath):
        if filepath in self._cache:
            return self._cache[filepath]
        if not os.path.exists(filepath):
            return None
        with open(filepath, 'r') as f:
            data = json.load(f)
        # 模拟将配置对象注册到全局管理器
        ConfigManager.register(self, filepath)
        self._cache[filepath] = data
        return data

    def unload_config(self, filepath):
        if filepath in self._cache:
            del self._cache[filepath]
            # 清理后仍保留文件路径引用
            self._loaded_files.append(filepath)

    def get_loaded_files(self):
        return self._loaded_files


class ConfigManager:
    _instances = {}

    @classmethod
    def register(cls, loader, path):
        # 存储引用，但不检查loader是否已被unload
        cls._instances[path] = loader

    @classmethod
    def get_loader(cls, path):
        return cls._instances.get(path)


def main():
    loader = ConfigLoader()
    path = "config.json"
    # 先加载配置
    loader.load_config(path)
    # 然后卸载
    loader.unload_config(path)
    # 之后通过全局管理器获取loader（此时loader对象仍存在但缓存已清）
    cached_loader = ConfigManager.get_loader(path)
    if cached_loader:
        # 此处尝试访问已被unload的loader的缓存（UAF场景）
        data = cached_loader._cache.get(path)  # 漏洞行：28
        print(data)


if __name__ == "__main__":
    main()

