import joblib
import os
import pandas as pd  


MODELS_DIR = 'models'
MODEL_PATH = os.path.join(MODELS_DIR, 'random_forest_model.pkl')
SCALER_PATH = os.path.join(MODELS_DIR, 'scaler.pkl')
FEATURE_COLUMNS_PATH = os.path.join(MODELS_DIR, 'feature_columns.pkl')


_loaded_model = None
_loaded_scaler = None
_feature_columns = []  

try:
    _loaded_model = joblib.load(MODEL_PATH)
    _loaded_scaler = joblib.load(SCALER_PATH)
    _feature_columns = joblib.load(FEATURE_COLUMNS_PATH)
    print("ML_UTILS: Modelo, Scaler e lista de colunas de features carregados com sucesso.")
except FileNotFoundError as e:
    print(
        f"ML_UTILS ERROR: Arquivo do modelo, scaler ou feature_columns não encontrado. {e}")
    print("Certifique-se de ter treinado e salvo o modelo, scaler e as colunas.")
except Exception as e:
    print(f"ML_UTILS ERROR: Erro ao carregar modelo/scaler/features: {e}")




def get_model():
    return _loaded_model


def get_scaler():
    return _loaded_scaler


def get_feature_columns():
    return _feature_columns


def predict_packet(processed_features_df):
    
    model = get_model()
    scaler = get_scaler()

    if model is None or scaler is None or not get_feature_columns():
        print("ML_UTILS: Modelo, scaler ou feature_columns não carregados. Não é possível fazer a predição.")
        return -1 

    try:

        prediction = model.predict(processed_features_df)
        
        return prediction[0]
    except Exception as e:
        print(f"ML_UTILS: Erro ao fazer predição: {e}")
        return -1
