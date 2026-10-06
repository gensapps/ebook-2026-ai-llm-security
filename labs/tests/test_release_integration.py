"""출판 검수에서 발견한 모듈 연결 오류의 회귀 검사. 외부 공격·API 호출 없음."""
import importlib
import pickle
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

attack = importlib.import_module('labs.attacker.agent.auto_pentest')
training = importlib.import_module('labs.adaptive.incremental_train')
scoring = importlib.import_module('labs.defender.score')


def test_unapproved_target_cannot_reach_recon():
    with patch.object(attack, 'nmap_scan') as scan:
        with pytest.raises(ValueError):
            attack.attack_one('outside-allowlist.invalid')
        scan.assert_not_called()


@pytest.mark.parametrize('decision', [[], None, {}, {'target': 'tgt-juice', 'exploit_method': 'sqlmap'},
    {'target': 'tgt-dvwa', 'exploit_method': 'shell'}])
def test_invalid_decision_cannot_execute(decision):
    with patch.object(attack, '_USE_MOCK', False), patch.object(attack.subprocess, 'run') as run:
        with pytest.raises(ValueError):
            attack.run_exploit('tgt-dvwa', decision)
        run.assert_not_called()


def test_denied_approval_cannot_execute():
    with patch.object(attack, '_USE_MOCK', False), patch.object(attack, 'require_approval', return_value=False), \
         patch.object(attack.subprocess, 'run') as run:
        assert attack.run_exploit('tgt-dvwa', {'target': 'tgt-dvwa', 'exploit_method': 'sqlmap'})['status'] == 'denied'
        run.assert_not_called()


def test_kill_switch_stops_before_recon():
    with patch.object(attack, 'check_kill_switch', side_effect=SystemExit(0)), patch.object(attack, 'nmap_scan') as scan:
        with pytest.raises(SystemExit):
            attack.attack_one('tgt-dvwa')
        scan.assert_not_called()


def test_mock_pipeline_uses_validated_decision():
    with patch.object(attack, 'audit'), patch.object(attack, '_USE_MOCK', True), \
         patch.object(attack, 'nmap_scan', return_value={'services': []}), \
         patch.object(attack, 'nuclei_scan', return_value=[]), \
         patch.object(attack, 'llm_with_shield', return_value={'target': 'tgt-dvwa', 'exploit_method': 'nuclei'}):
        assert attack.attack_one('tgt-dvwa')['status'] == 'mock'


def test_notebook_model_can_be_incrementally_trained():
    from sklearn.feature_extraction.text import HashingVectorizer
    from sklearn.linear_model import SGDClassifier
    vec = HashingVectorizer(n_features=32, alternate_sign=False)
    model = SGDClassifier(random_state=42)
    model.partial_fit(vec.transform(['normal', 'attack']), [0, 1], classes=[0, 1])
    with tempfile.TemporaryDirectory() as tmp, patch.object(training, '_USE_MOCK', False):
        path = Path(tmp) / 'model.pkl'
        path.write_bytes(pickle.dumps({'model': model, 'vec': vec, 'version': 2}))
        assert training.incremental_retrain(str(path), [{'log': {'payload': 'normal'}, 'label': {'category': 'BENIGN'}}]) == 3
        updated = pickle.loads(path.read_bytes())
        assert updated['model'].t_ > model.t_


def test_score_requires_explicit_hostname_ip_mapping():
    def events(name):
        return ([{'phase': 'exploit', 'target': 'tgt-dvwa'}] if name.startswith('attack') else
                [{'conn': {'dst': '172.30.0.2'}, 'verdict': {'route': 'review'}}])
    with patch.object(scoring, '_load', side_effect=events):
        with pytest.raises(ValueError):
            scoring.score({})
        assert scoring.score({'tgt-dvwa': '172.30.0.2'})['rate'] == 1


def test_live_training_missing_model_is_not_mock_success(tmp_path):
    with patch.object(training, '_USE_MOCK', False):
        with pytest.raises(FileNotFoundError):
            training.incremental_retrain(str(tmp_path / 'missing.pkl'),
                [{'log': {'payload': 'normal'}, 'label': {'category': 'BENIGN'}}])
        assert not (tmp_path / 'missing.pkl.meta').exists()


def test_live_missing_zeek_log_is_not_synthetic_flow(tmp_path):
    parser = importlib.import_module('labs.defender.parse_zeek')
    with patch.object(parser, '_USE_MOCK', False), patch.object(parser, 'ZEEK_LOG', tmp_path / 'missing.log'):
        with pytest.raises(FileNotFoundError):
            list(parser.stream_conn_log())
