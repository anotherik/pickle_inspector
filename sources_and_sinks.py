# pickle_inspector/sources_and_sinks.py

# ⚠️ Dangerous functions that deserialize arbitrary objects (sinks)
SINKS = {
    "pickle.load",
    "pickle.loads",
    "pickle.Unpickler.load",
    "joblib.load",
    "cloudpickle.load",
    "cloudpickle.loads",
    "dill.load",
    "dill.loads",
    "marshal.load",
    "marshal.loads",
    "shelve.open",        # Indirect: opens pickle-backed object storage
    "yaml.load",          # PyYAML (unsafe unless using safe_load)
}

# 🔺 Known taint sources (untrusted inputs)
SOURCES = {
    "input",
    "sys.argv",
    "os.environ.get",
    "os.getenv",
    "request.form.get",
    "request.form.__getitem__",
    "request.args.get",
    "request.args.__getitem__",
    "request.json.get",
    "request.json.__getitem__",
    "request.data",
    "request.get_json",
    "request.files.__getitem__",
    "request.files.get",
    "request.POST.get",         # Django
    "request.GET.get",
    "request.body",
    "request.FILES.get",
    "argparse.Namespace",
    "urllib.request.urlopen",
    "requests.get",
    "socket.recv",
}

