class Config:
    SQLALCHEMY_DATABASE_URI = "sqlite:///app.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = "devkey-1234-super-temp"
    JWT_SECRET_KEY = "jwt-super-temp-key-5678"
