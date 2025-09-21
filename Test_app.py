import pytest
from app import app, TEST_SAMPLES, binary_features, multi_class_features

# Set up the Flask test client
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

# Core Functionality Tests 

def test_benign_binary_scan(client):
    """Tests if a known benign sample is correctly classified in binary mode."""
    response = client.post('/', data={
        'flow_data': TEST_SAMPLES['Benign'],
        'analysis_mode': 'binary'
    })
    assert response.status_code == 200
    #Checking for Title Case "Benign"
    assert b'CLASSIFICATION: Benign' in response.data

def test_attack_multi_class_scan(client):
    """Tests if a known Botnet sample is correctly classified in multi-class mode."""
    response = client.post('/', data={
        'flow_data': TEST_SAMPLES['Botnet'],
        'analysis_mode': 'multi'
    })
    assert response.status_code == 200
    # Checking for Title Case "Botnet"
    assert b'CLASSIFICATION: Botnet' in response.data

#Error Handling and Input Validation Tests

def test_empty_input(client):
    """Tests if submitting an empty form returns the correct error."""
    response = client.post('/', data={'flow_data': ' ', 'analysis_mode': 'binary'})
    assert response.status_code == 200
    assert b'Error: Please enter a network flow vector to analyze.' in response.data

def test_malformed_input_characters(client):
    """Tests if input with invalid characters returns an error."""
    response = client.post('/', data={'flow_data': 'abc,123,xyz', 'analysis_mode': 'binary'})
    assert response.status_code == 200
    assert b'Error: Input contains invalid characters.' in response.data

def test_incorrect_feature_count_binary(client):
    """Tests binary mode with the wrong number of features."""
    response = client.post('/', data={'flow_data': '1,2,3', 'analysis_mode': 'binary'})
    assert response.status_code == 200
    assert f"Expected {len(binary_features)}".encode('utf-8') in response.data

def test_incorrect_feature_count_multi(client):
    """Tests multi-class mode with the wrong number of features."""
    response = client.post('/', data={'flow_data': '1,2,3', 'analysis_mode': 'multi'})
    assert response.status_code == 200
    assert f"Expected {len(multi_class_features)}".encode('utf-8') in response.data


def test_confidence_score_present(client):
    """Tests if the confidence score is displayed in the output."""
    response = client.post('/', data={
        'flow_data': TEST_SAMPLES['Benign'],
        'analysis_mode': 'binary'
    })
    assert response.status_code == 200
    assert b'(CONFIDENCE:' in response.data
    assert b'%)' in response.data

def test_reasoning_not_present_for_benign(client):
    """Tests that no reasoning text is shown for a benign verdict."""
    response = client.post('/', data={
        'flow_data': TEST_SAMPLES['Benign'],
        'analysis_mode': 'binary'
    })
    assert response.status_code == 200
    # Checking for Title Case "Benign"
    assert b'CLASSIFICATION: Benign' in response.data
    assert b'Reasoning:' not in response.data