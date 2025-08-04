# pickle_inspector/sources_and_sinks.py

# ⚠️ Dangerous functions that deserialize arbitrary objects (sinks)
SINKS = {
    "pickle.load",                       # Standard pickle deserialization (file-based)
    "pickle.loads",                      # Standard pickle deserialization (in-memory)
    "pickle.Unpickler.load",             # Custom unpickler-based deserialization
    "joblib.load",                       # Joblib loader using pickle internally
    "cloudpickle.load",                  # Cloudpickle supports extended objects, uses pickle
    "cloudpickle.loads",                 # In-memory version of cloudpickle.load
    "dill.load",                         # Dill extends pickle; supports more object types
    "dill.loads",                        # In-memory version of dill.load
    "marshal.load",                      # Deserializes Python bytecode (unsafe)
    "marshal.loads",                     # In-memory version of marshal.load
    "shelve.open",                       # Opens persistent dictionary backed by pickle
    "yaml.load",                         # PyYAML unsafe load (use safe_load instead)
    "torch.load",                        # PyTorch model loader — uses pickle internally
    "torch.jit.load",                    # TorchScript model loader — also uses pickle
    "numpy.load",                        # Loads .npy/.npz files — unsafe if allow_pickle=True
    "pandas.read_pickle",                # Loads pandas DataFrames via pickle
    "sklearn.externals.joblib.load",     # Legacy import path — same as joblib.load
    "keras.models.load_model",           # Keras model loader — may fallback to pickle inside HDF5
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

