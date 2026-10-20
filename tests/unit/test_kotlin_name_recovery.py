"""Pinned-shape tests for the Kotlin name recovery parser.

The shipped script (`skills/apk-reverse/scripts/kotlin_name_recovery.py`) is measured by
its embedded fixtures; these tests pin the same shapes independently so a regex regression
fails in CI rather than on a real jadx export. Every fixture here is a *shape*, written by
this repository, not a fragment of any real target.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills',
                                'apk-reverse', 'scripts'))

from kotlin_name_recovery import (  # noqa: E402
    FIXTURE_DEBUG, FIXTURE_METADATA, FIXTURE_PLAIN, FIXTURE_RENAMED, mine_tree,
    recover_real_name, write_map,
)


def test_debug_metadata_strips_dollar_scope():
    # `$fetch$1` is inner/lambda scope; the declaring class is everything before the first $.
    real, source = recover_real_name(FIXTURE_DEBUG)
    assert real == 'com.example.feature.account.AccountRepositoryImpl'
    assert source == 'debug_metadata'


def test_metadata_d2_takes_first_non_stdlib_descriptor():
    real, source = recover_real_name(FIXTURE_METADATA)
    assert real == 'com.example.feature.login.LoginViewModel'
    assert source == 'metadata_d2'


def test_renamed_comment_is_the_weakest_fallback():
    real, source = recover_real_name(FIXTURE_RENAMED)
    assert real == 'com.example.core.network.ApiClient'
    assert source == 'renamed_comment'


def test_plain_java_recovers_nothing():
    # No annotation and no rename comment: the honest result is (None, None), not a guess.
    real, source = recover_real_name(FIXTURE_PLAIN)
    assert real is None and source is None


def test_debug_metadata_outranks_everything():
    # A file carrying both sources must resolve through @DebugMetadata: it is a true
    # declaring-class FQN, while d2 descriptors are a hint.
    both = FIXTURE_DEBUG + '\n@Metadata(d2 = {"Lcom/example/other/WrongHint;"})\n'
    real, source = recover_real_name(both)
    assert real == 'com.example.feature.account.AccountRepositoryImpl'
    assert source == 'debug_metadata'


def test_mine_tree_skips_third_party_and_maps_the_rest(tmp_path):
    src = tmp_path / 'sources'
    for rel, body in (('nq/a.java', FIXTURE_DEBUG),
                      ('z/C0123x.java', FIXTURE_RENAMED),
                      ('kotlin/x/Keep.java', FIXTURE_DEBUG)):
        path = src / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding='utf-8')
    mapping, counts = mine_tree(str(src))
    # kotlin.* is skipped as already-real even though its fixture carries @DebugMetadata.
    assert set(mapping) == {'nq.a', 'z.C0123x'}
    assert counts == {'debug_metadata': 1, 'renamed_comment': 1}

    out = tmp_path / 'map'
    packages = write_map(mapping, counts, str(out))
    assert packages == 2
    tsv = (out / 'mapping.tsv').read_text(encoding='utf-8')
    assert 'nq.a\tcom.example.feature.account.AccountRepositoryImpl\tdebug_metadata' in tsv
    # by_package files are keyed by the ORIGINAL package, which is the lookup a reader wants.
    assert (out / 'by_package' / 'com_example_core_network.tsv').exists()
