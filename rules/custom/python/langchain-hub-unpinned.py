from langchain import hub


def bad_owner_prompt():
    # ruleid: sast.python.langchain-hub-unpinned
    return hub.pull("hwchase17/react")


def bad_no_owner():
    # ruleid: sast.python.langchain-hub-unpinned
    return hub.pull("rag-prompt")


def bad_with_kwargs():
    # ruleid: sast.python.langchain-hub-unpinned
    return hub.pull("acme/summarize", include_model=True)


def ok_pinned():
    # ok: sast.python.langchain-hub-unpinned
    return hub.pull("owner/prompt:abc1234")


def ok_pinned_long_hash():
    # ok: sast.python.langchain-hub-unpinned
    return hub.pull("acme/summarize:5a1c9f0e22b4", include_model=True)


def ok_dynamic_name(name):
    # ok: sast.python.langchain-hub-unpinned
    return hub.pull(name)


def ok_other_pull(repo):
    # ok: sast.python.langchain-hub-unpinned
    return repo.pull("origin")
