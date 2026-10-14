"""전작 14장 이진 RF 산출물을 후속 도서의 로그 라우터에 연결한다."""
from pathlib import Path
import math
import pickle
import pandas as pd


class BinaryArtifactScorer:
    def __init__(self, path):
        # pickle은 직접 학습·저장한 신뢰할 수 있는 파일만 읽는다.
        with Path(path).open('rb') as stream:
            artifact = pickle.load(stream)
        self.preprocessor = artifact['preprocessor']
        self.model = artifact['model']
        columns = artifact.get('feature_columns')
        if columns is None:
            columns = list(self.preprocessor.feature_names_in_)
        self.feature_columns = list(columns)
        self.positive_label = artifact.get('positive_label', 1)
        classes = list(self.model.classes_)
        if len(classes) != 2 or self.positive_label not in classes:
            raise ValueError('정상/공격 이진 모델과 positive_label이 필요합니다.')
        self.positive_index = classes.index(self.positive_label)

    def __call__(self, log):
        features = log.get('features')
        if not isinstance(features, dict):
            raise ValueError('수집기가 계산한 연결 특성을 features 객체로 전달하세요.')
        missing = set(self.feature_columns) - set(features)
        if missing:
            raise ValueError(f'필수 연결 특성 누락: {sorted(missing)}')
        frame = pd.DataFrame([{key: features[key] for key in self.feature_columns}])
        if frame.isna().any().any():
            raise ValueError('특성에 결측값이 있습니다.')
        transformed = self.preprocessor.transform(frame)
        score = float(self.model.predict_proba(transformed)[0, self.positive_index])
        if not math.isfinite(score) or not 0 <= score <= 1:
            raise ValueError('유효하지 않은 모델 점수입니다.')
        return score
