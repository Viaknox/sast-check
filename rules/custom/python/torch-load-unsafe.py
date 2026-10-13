import torch


def bad_basic(path):
    # ruleid: sast.python.torch-load-unsafe
    return torch.load(path, weights_only=False)


def bad_with_map_location(path):
    # ruleid: sast.python.torch-load-unsafe
    return torch.load(path, map_location="cpu", weights_only=False)


def bad_file_object(fh):
    # ruleid: sast.python.torch-load-unsafe
    state = torch.load(fh, weights_only=False, mmap=True)
    return state


def ok_default(path):
    # ok: sast.python.torch-load-unsafe
    return torch.load(path)


def ok_explicit_true(path):
    # ok: sast.python.torch-load-unsafe
    return torch.load(path, weights_only=True)


def ok_map_location_only(path):
    # ok: sast.python.torch-load-unsafe
    return torch.load(path, map_location="cpu")


def ok_other_loader(path):
    import numpy as np
    # ok: sast.python.torch-load-unsafe
    return np.load(path, allow_pickle=False)
