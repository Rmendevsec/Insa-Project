# safe_api_check.py  (Run only on targets you have permission to test)
import requests, sys, yaml, json
from jsonschema import validate, ValidationError
from openapi_spec_validator import validate_spec
from time import sleep
from rich import print

RATE_LIMIT = 1.0  # seconds between requests (safe mode)

def load_openapi(path):
    with open(path) as f:
        spec = yaml.safe_load(f)
    validate_spec(spec)  # will raise if invalid
    return spec

def simple_get(url, headers=None):
    r = requests.get(url, headers=headers, timeout=10)
    return r

def check_excessive_data(spec, path, method, response_json):
    # Very simple check: compare returned keys with schema properties if present
    try:
        responses = spec['paths'][path][method]['responses']
        # choose 200 response schema if exists
        schema = None
        if '200' in responses and 'content' in responses['200']:
            content = responses['200']['content']
            # naive: pick application/json
            if 'application/json' in content:
                schema = content['application/json']['schema']
        if schema and 'properties' in schema:
            allowed = set(schema['properties'].keys())
            returned = set(response_json.keys()) if isinstance(response_json, dict) else set()
            extra = returned - allowed
            if extra:
                return True, list(extra)
    except Exception:
        pass
    return False, []

if __name__ == "__main__":
    # Example usage: python safe_api_check.py openapi.yml http://localhost:5000
    if len(sys.argv) < 3:
        print("Usage: safe_api_check.py openapi.yml base_url")
        sys.exit(1)
    spec = load_openapi(sys.argv[1])
    base = sys.argv[2].rstrip('/')
    headers = {}  # fill in with token only if you have consent
    for p, pdef in spec.get('paths', {}).items():
        full = base + p.replace('{','{')  # naive
        if 'get' in pdef:
            print(f"[bold]Checking GET {full}[/bold]")
            r = simple_get(base + p.replace('{','').replace('}',''), headers=headers)
            sleep(RATE_LIMIT)
            try:
                j = r.json()
            except Exception:
                j = None
            if j and 'get' in pdef:
                extra_found, extras = check_excessive_data(spec, p, 'get', j)
                if extra_found:
                    print(f"[red]Excessive fields returned:[/red] {extras}")
                else:
                    print("[green]No excessive fields detected (by simple heuristic).[/green]")
