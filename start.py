#!/usr/bin/env python3
import os
import sys
from app import app

if __name__ == '__main__':
    # Wasmer expects the app to listen on 0.0.0.0:8000
    port = int(os.environ.get('PORT', 8000))
    print(f"Starting Flask app on 0.0.0.0:{port}", file=sys.stderr)
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
