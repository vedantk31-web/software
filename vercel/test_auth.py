import pytest
from flask import json
from app import create_app

@pytest.fixture
def app():
    app = create_app()
    yield app

@pytest.fixture
def client(app):
    return app.test_client()

def test_login(client):
    # Test login endpoint
    data = {
        'username': 'testuser',
        'password': 'testpassword'
    }
    response = client.post('/auth/login', json=data)
    assert response.status_code == 200
    assert 'access_token' in json.loads(response.data)
    print("Login test passed successfully.")  # Debug output

def test_protected_route(client):
    # Test protected endpoint
    response = client.get('/auth/protected')
    assert response.status_code == 401  # Unauthorized without token
    print("Protected route test passed successfully.")  # Debug output

    # Add more tests with valid access token as needed