"""Pinned-shape tests for the JS obfuscation family detector.

The detector (`skills/apk-reverse/scripts/js_obf_detect.py`) scores families by weighted
probes (hint token = 10, content regex = 3). These tests pin the routing decisions that
matter: each fixture selects its own family as the top pick, a hint outranks a single
content hit, plain code routes to the generic ladder, and the huge-literal threshold is
a parameter the caller can lower for small samples.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills',
                                'apk-reverse', 'scripts'))

from js_obf_detect import (  # noqa: E402
    FIXTURES, _jsvmp_fixture, pipeline_for, residue_metrics, score_families,
)


def test_each_fixture_wins_its_own_family():
    for fam_id, body in FIXTURES.items():
        detections = score_families(body, '', 'sample.js', 1500)
        assert detections, 'no detection for %s' % fam_id
        assert detections[0]['id'] == fam_id, (fam_id, detections)


def test_jsvmp_entry_needs_the_literal_threshold():
    # The huge-literal probes only fire at the configured length: with the default 1500
    # threshold a 210-char literal scores nothing for the literal itself, and the fixture
    # is detected (if at all) through the dependency-array probe alone. Lowering
    # --min-literal is the documented way to classify small samples.
    body = _jsvmp_fixture(200)
    default_detections = score_families(body, '', 's.js', 1500)
    reasons = [r for d in default_detections if d['id'] == 'jsvmp_entry' for r in d['reasons']]
    assert all('opcode literal' not in r for r in reasons), reasons
    detections = score_families(body, '', 's.js', 200)
    assert detections and detections[0]['id'] == 'jsvmp_entry', detections
    assert any('opcode literal' in r for r in detections[0]['reasons'])


def test_hint_beats_a_single_content_hit():
    # A human hint is worth 10; one content regex is worth 3. The routing consequence:
    # a named vendor hint wins over incidental structural overlap.
    detections = score_families('plain text', 'some obfuscator lineage', 'x.js', 1500)
    assert detections[0]['id'] == 'ob_string_array'
    assert detections[0]['score'] == 10


def test_plain_code_is_generic_ladder():
    assert score_families('function add(a, b) { return a + b; }\n', '', 'x.js', 1500) == []
    assert pipeline_for('generic')[0] == 'normalize' and pipeline_for('generic')[-1] == 'normalize'


def test_pipelines_differ_per_family():
    # The whole point of detection: the string-array lineage decodes FIRST, the
    # opcode-if-chain family goes straight to if-chain conversion.
    assert pipeline_for('ob_string_array')[2] == 'string_array_pass'
    assert 'if_chain_to_switch' in pipeline_for('opcode_if_chain')
    assert pipeline_for('ob_string_array') != pipeline_for('opcode_if_chain')


def test_residue_metrics_are_textual_proxies():
    r = residue_metrics(FIXTURES['ob_string_array'])
    # The 3+ hex-char filter counts _0x4ab1 but not short names (_0x1, _0x9f).
    assert r['mangled_identifiers'] == 1
    assert r['eval_calls'] == 0
    assert r['lines'] >= 3
