import re
import sys

from gunicorn.app.wsgiapp import run

print('\n'.join(sys.path))
# use this entrypoint to start the proxy from the IDE

if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw?|\.exe)?$', '', sys.argv[0])
    sys.exit(run())

