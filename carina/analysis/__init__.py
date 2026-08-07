"""Log ingestion and exception clustering.

Pure standard-library analysis that turns a stream of log text into structured,
deduplicated failure clusters. It produces the *input* to a proposal -- it never
decides anything and never touches the filesystem outside of reading the log it is
told to tail. The authorization boundary lives entirely downstream in ``carina.policy``.
"""
