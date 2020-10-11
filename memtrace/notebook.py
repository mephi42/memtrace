from contextlib import contextmanager
import io
import json
import os
import shutil
import subprocess
import tarfile
import webbrowser

import memtrace

CONFIG_FILE = '/home/jovyan/.local/share/jupyter/runtime/nbserver-6.json'


def get_token(cid):
    n_retries = 30
    for retry in range(n_retries):
        try:
            config_tar = subprocess.check_output(
                args=['docker', 'cp', f'{cid}:{CONFIG_FILE}', '-'],
                stderr=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError:
            if retry == n_retries - 1:
                raise
            continue
    tarfp = tarfile.open(fileobj=io.BytesIO(config_tar))
    member = tarfp.getmember(os.path.basename(CONFIG_FILE))
    config = json.load(tarfp.extractfile(member))
    return config['token']


def get_host_port(cid, port):
    query = f'(index (index .NetworkSettings.Ports "{port}/tcp") 0).HostPort'
    return int(subprocess.check_output([
        'docker', 'inspect', '--format={{' + query + '}}', cid]))


@contextmanager
def open_notebook(echo):
    echo('Starting a container...')
    cwd = os.getcwd()
    cid = subprocess.check_output([
        'docker', 'run',
        '--detach',
        '--publish-all',
        '--rm',
        f'--volume={cwd}:{cwd}',
        f'--workdir={cwd}',
        f'mephi42/memtrace-jupyter:{memtrace.__version__}',
    ]).decode().strip()
    try:
        echo('Querying a port...')
        port = get_host_port(cid, 8888)
        echo('Obtaining a token...')
        token = get_token(cid)
        default_ipynb = os.path.join(
            os.path.dirname(__file__), 'memtrace.ipynb')
        if not os.path.exists(os.path.basename(default_ipynb)):
            shutil.copy(default_ipynb, '.')
        url = f'http://127.0.0.1:{port}/notebooks/memtrace.ipynb?token={token}'
        echo(f'Opening {url}...')
        webbrowser.open(url)
        yield
    finally:
        subprocess.check_call(['docker', 'rm', '-f', cid])
