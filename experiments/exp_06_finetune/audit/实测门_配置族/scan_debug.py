import sys
def scan(f):
    sys.argv = ['checkov', '-f', f, '-o', 'csv']
    from checkov.main import Checkov
    rc = Checkov(argv=sys.argv).run()
    return rc
rc = scan('Dockerfile_bad')
print('rc =', rc)
