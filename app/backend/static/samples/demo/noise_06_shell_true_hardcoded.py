import subprocess

result = subprocess.run("echo 'hello world'", shell=True, capture_output=True)
print(result.stdout.decode())
