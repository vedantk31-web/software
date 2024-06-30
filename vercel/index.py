import os
import sys

# Add the parent directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wsgi import app as flask_app

def handler(event, context):
    return flask_app(event, context)
