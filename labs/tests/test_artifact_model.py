"""전작 RF 산출물의 컬럼·라벨 계약과 실패 경로를 실제 sklearn 객체로 검사한다."""
import pickle
import sys
from pathlib import Path

import pandas as pd
import pytest
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from artifact_model import BinaryArtifactScorer


@pytest.fixture
def artifact(tmp_path):
    frame = pd.DataFrame({'duration': [0, 1, 20, 21], 'service': ['http', 'http', 'ssh', 'ssh']})
    prep = ColumnTransformer([('num', StandardScaler(), ['duration']),
                              ('cat', OneHotEncoder(handle_unknown='ignore'), ['service'])])
    model = RandomForestClassifier(n_estimators=12, random_state=42).fit(
        prep.fit_transform(frame), [0, 0, 1, 1])
    data = {'preprocessor': prep, 'model': model,
            'feature_columns': ['duration', 'service'], 'positive_label': 1}
    path = tmp_path / 'rf.pickle'
    path.write_bytes(pickle.dumps(data))
    return path, data


def test_real_column_transformer_and_input_order(artifact):
    path, data = artifact
    score = BinaryArtifactScorer(path)
    row = {'service': 'ssh', 'duration': 20}
    expected = data['model'].predict_proba(data['preprocessor'].transform(pd.DataFrame([row])))[0, 1]
    assert score({'features': row}) == expected
    assert 0 <= score({'features': {'service': 'unseen', 'duration': 2}}) <= 1


@pytest.mark.parametrize('event', [{}, {'features': []}, {'features': {'duration': 1}},
    {'features': {'duration': None, 'service': 'http'}}])
def test_missing_features_are_not_invented(artifact, event):
    with pytest.raises(ValueError):
        BinaryArtifactScorer(artifact[0])(event)


def test_positive_label_is_not_fixed_column_one(artifact):
    path, data = artifact
    original = BinaryArtifactScorer(path)({'features': {'duration': 20, 'service': 'ssh'}})
    data['positive_label'] = 0
    path.write_bytes(pickle.dumps(data))
    assert BinaryArtifactScorer(path)({'features': {'duration': 20, 'service': 'ssh'}}) == pytest.approx(1-original)
    data['positive_label'] = 9
    path.write_bytes(pickle.dumps(data))
    with pytest.raises(ValueError):
        BinaryArtifactScorer(path)
